// SPDX-License-Identifier: MIT

package policy

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestForgetRemovesRateAndBudgetState(t *testing.T) {
	engine := NewEngine()
	engine.Register(&Policy{
		Name:        "limited",
		RateLimit:   1,
		RateWindow:  time.Hour,
		MaxRequests: 1,
	})
	request := httptest.NewRequest("GET", "https://api.example.com/", nil)
	if deny := engine.Check("limited", "root-token-id", request); deny != nil {
		t.Fatalf("first request denied: %v", deny)
	}
	if len(engine.rates) != 1 || len(engine.budgets) != 1 {
		t.Fatalf("accounting state = %d rate, %d budget; want one each", len(engine.rates), len(engine.budgets))
	}

	engine.Forget("root-token-id")
	if len(engine.rates) != 0 || len(engine.budgets) != 0 {
		t.Fatalf("accounting state survived cleanup: %d rate, %d budget", len(engine.rates), len(engine.budgets))
	}
	if deny := engine.Check("limited", "root-token-id", request); deny != nil {
		t.Fatalf("fresh accounting state inherited an old denial: %v", deny)
	}
}
