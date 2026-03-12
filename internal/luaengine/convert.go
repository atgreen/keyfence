// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

package luaengine

import (
	lua "github.com/yuin/gopher-lua"
)

// goToLua converts a Go value (from encoding/json) to a Lua value.
func goToLua(L *lua.LState, v interface{}) lua.LValue {
	switch val := v.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(val)
	case float64:
		return lua.LNumber(val)
	case string:
		return lua.LString(val)
	case map[string]interface{}:
		tbl := L.NewTable()
		for k, v := range val {
			tbl.RawSetString(k, goToLua(L, v))
		}
		return tbl
	case []interface{}:
		tbl := L.NewTable()
		for i, v := range val {
			tbl.RawSetInt(i+1, goToLua(L, v))
		}
		return tbl
	default:
		return lua.LNil
	}
}

// luaToGo converts a Lua value back to a Go value.
func luaToGo(v lua.LValue) interface{} {
	switch val := v.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(val)
	case lua.LNumber:
		return float64(val)
	case lua.LString:
		return string(val)
	case *lua.LTable:
		// Detect if it's an array (sequential integer keys starting at 1)
		maxN := val.MaxN()
		if maxN > 0 {
			arr := make([]interface{}, 0, maxN)
			for i := 1; i <= maxN; i++ {
				arr = append(arr, luaToGo(val.RawGetInt(i)))
			}
			return arr
		}
		m := make(map[string]interface{})
		val.ForEach(func(k, v lua.LValue) {
			if ks, ok := k.(lua.LString); ok {
				m[string(ks)] = luaToGo(v)
			}
		})
		return m
	default:
		return nil
	}
}
