// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@redhat.com>

// Package telemetry initializes OpenTelemetry tracing for KeyFence.
//
// Configuration is via standard OTel environment variables:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT  — OTLP endpoint (default: http://localhost:4318)
//	OTEL_SERVICE_NAME            — service name (default: keyfence)
//	OTEL_TRACES_EXPORTER         — set to "none" to disable
//
// If no OTLP endpoint is reachable, traces are silently dropped (noop).
package telemetry

import (
	"context"
	"log"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/keyfence/keyfence"

// Tracer returns the global KeyFence tracer.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// Init initializes the OTel trace provider and returns a shutdown function.
// If OTEL_TRACES_EXPORTER is "none" or unset and no endpoint is configured,
// a noop provider is used.
func Init(ctx context.Context, version string) (shutdown func(context.Context) error, err error) {
	if os.Getenv("OTEL_TRACES_EXPORTER") == "none" {
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "keyfence"
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			attribute.String("service.version", version),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	log.Printf("otel tracing enabled (service=%s)", serviceName)

	return tp.Shutdown, nil
}

// WithSpanAttributes is a convenience for trace.WithAttributes.
func WithSpanAttributes(attrs ...attribute.KeyValue) trace.SpanStartOption {
	return trace.WithAttributes(attrs...)
}
