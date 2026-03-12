// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package luaengine provides a sandboxed Lua VM pool for evaluating
// response rules against JSON API responses.
//
// Scripts receive three globals:
//   - response       — parsed JSON response body (table)
//   - response_headers — response HTTP headers (table)
//   - response_status  — HTTP status code (number)
//   - state          — mutable table persisted across requests for the same token
//
// Scripts return nil (no action) or a table: {action="revoke", reason="..."}.
package luaengine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// Action is the result of a Lua script evaluation.
type Action struct {
	Action string // "revoke" or "alert"
	Reason string
}

// EvalInput holds the data exposed to Lua scripts.
type EvalInput struct {
	ResponseBody    map[string]interface{}
	ResponseHeaders map[string]string
	ResponseStatus  int
	State           map[string]interface{} // mutable; updated in place
}

// Engine manages a pool of sandboxed Lua VMs.
type Engine struct {
	pool            sync.Pool
	scriptCache     sync.Map // sha256 → *lua.FunctionProto
	maxInstructions int
	scriptTimeout   time.Duration
}

// New creates a Lua engine with default limits.
func New() *Engine {
	e := &Engine{
		maxInstructions: 100_000,
		scriptTimeout:   500 * time.Millisecond,
	}
	e.pool.New = func() interface{} {
		return e.newSandboxedVM()
	}
	return e
}

func (e *Engine) newSandboxedVM() *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})

	// Open only safe libraries
	lua.OpenBase(L)
	lua.OpenTable(L)
	lua.OpenString(L)
	lua.OpenMath(L)

	// Remove dangerous base functions
	for _, name := range []string{
		"dofile", "loadfile", "load", "require",
		"rawset", "rawget", "rawequal", "rawlen",
		"collectgarbage", "newproxy",
	} {
		L.SetGlobal(name, lua.LNil)
	}

	return L
}

func (e *Engine) getVM() *lua.LState {
	return e.pool.Get().(*lua.LState)
}

func (e *Engine) putVM(L *lua.LState) {
	// Clear per-request globals
	L.SetGlobal("response", lua.LNil)
	L.SetGlobal("response_headers", lua.LNil)
	L.SetGlobal("response_status", lua.LNil)
	L.SetGlobal("state", lua.LNil)
	e.pool.Put(L)
}

// compile compiles a script string, caching the result.
func (e *Engine) compile(script string) (*lua.FunctionProto, error) {
	key := sha256.Sum256([]byte(script))
	if cached, ok := e.scriptCache.Load(key); ok {
		return cached.(*lua.FunctionProto), nil
	}

	chunk, err := parse.Parse(strings.NewReader(script), "<rule>")
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	proto, err := lua.Compile(chunk, "<rule>")
	if err != nil {
		return nil, fmt.Errorf("compile error: %w", err)
	}

	e.scriptCache.Store(key, proto)
	return proto, nil
}

// Eval runs a Lua script against the given input.
// Returns nil action if the script returns nil or no action table.
// The input.State map is updated in place with any mutations.
func (e *Engine) Eval(script string, input *EvalInput) (*Action, error) {
	proto, err := e.compile(script)
	if err != nil {
		return nil, err
	}

	L := e.getVM()
	defer e.putVM(L)

	// Set timeout context
	ctx, cancel := context.WithTimeout(context.Background(), e.scriptTimeout)
	defer cancel()
	L.SetContext(ctx)
	defer L.RemoveContext()

	// Inject globals
	L.SetGlobal("response", goToLua(L, mapToInterface(input.ResponseBody)))
	L.SetGlobal("response_status", lua.LNumber(input.ResponseStatus))

	headers := L.NewTable()
	for k, v := range input.ResponseHeaders {
		headers.RawSetString(k, lua.LString(v))
	}
	L.SetGlobal("response_headers", headers)

	stateTable := goToLua(L, mapToInterface(input.State))
	L.SetGlobal("state", stateTable)

	// Run the compiled script
	fn := L.NewFunctionFromProto(proto)
	L.Push(fn)
	if err := L.PCall(0, 1, nil); err != nil {
		return nil, fmt.Errorf("script error: %w", err)
	}

	// Read state back
	newState := L.GetGlobal("state")
	if tbl, ok := newState.(*lua.LTable); ok {
		updated := luaToGo(tbl)
		if m, ok := updated.(map[string]interface{}); ok {
			// Update in place
			for k := range input.State {
				delete(input.State, k)
			}
			for k, v := range m {
				input.State[k] = v
			}
		}
	}

	// Read return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, nil
	}

	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, nil
	}

	action := tbl.RawGetString("action")
	if action == lua.LNil {
		return nil, nil
	}

	result := &Action{
		Action: action.String(),
	}
	if reason := tbl.RawGetString("reason"); reason != lua.LNil {
		result.Reason = reason.String()
	}

	return result, nil
}

// mapToInterface converts map[string]interface{} to interface{} for goToLua.
func mapToInterface(m map[string]interface{}) interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return interface{}(m)
}
