package zapwriter

import (
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Logger           string `toml:"logger"`            // handler name, default empty
	File             string `toml:"file"`              // filename, "stderr", "stdout", "empty" (=="stderr"), "none"
	Level            string `toml:"level"`             // "debug", "info", "warn", "error", "dpanic", "panic", and "fatal"
	Encoding         string `toml:"encoding"`          // "json", "console"
	EncodingTime     string `toml:"encoding-time"`     // "millis", "nanos", "epoch", "iso8601"
	EncodingDuration string `toml:"encoding-duration"` // "seconds", "nanos", "string"
	Type             string `toml:"type"`              // for rsyslog: "err" (default), "access"
}

func NewConfig() Config {
	return Config{
		File:             "stderr",
		Level:            "info",
		Encoding:         "mixed",
		EncodingTime:     "iso8601",
		EncodingDuration: "seconds",
	}
}

func (c *Config) Clone() *Config {
	clone := *c
	return &clone
}

func (c *Config) Check() error {
	_, err := c.build(true)
	return err
}

func (c *Config) BuildLogger() (*zap.Logger, error) {
	return c.build(false)
}

func (c *Config) encoder() (zapcore.Encoder, zap.AtomicLevel, error) {
	u, err := url.Parse(c.File)
	atomicLevel := zap.NewAtomicLevel()

	if err != nil {
		return nil, atomicLevel, err
	}

	level := u.Query().Get("level")
	if level == "" {
		level = c.Level
	}

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, atomicLevel, err
	}

	atomicLevel.SetLevel(zapLevel)

	var encoder zapcore.Encoder
	if u.Scheme == "rsyslog" {
		encoder, err = c.encoderRsyslog(u)
	} else {
		encoder, err = c.encoderLocal(u)
	}
	if err != nil {
		return nil, atomicLevel, err
	}

	return encoder, atomicLevel, nil
}

func (c *Config) encoderLocal(u *url.URL) (zapcore.Encoder, error) {
	encoding := u.Query().Get("encoding")
	if encoding == "" {
		encoding = c.Encoding
	}

	encodingTime := u.Query().Get("encoding-time")
	if encodingTime == "" {
		encodingTime = c.EncodingTime
	}

	encodingDuration := u.Query().Get("encoding-duration")
	if encodingDuration == "" {
		encodingDuration = c.EncodingDuration
	}

	var encoderTime zapcore.TimeEncoder

	switch strings.ToLower(encodingTime) {
	case "millis":
		encoderTime = zapcore.EpochMillisTimeEncoder
	case "nanos":
		encoderTime = zapcore.EpochNanosTimeEncoder
	case "epoch":
		encoderTime = zapcore.EpochTimeEncoder
	case "iso8601", "":
		encoderTime = zapcore.ISO8601TimeEncoder
	default:
		return nil, fmt.Errorf("unknown time encoding %#v", encodingTime)
	}

	var encoderDuration zapcore.DurationEncoder
	switch strings.ToLower(encodingDuration) {
	case "seconds", "":
		encoderDuration = zapcore.SecondsDurationEncoder
	case "nanos":
		encoderDuration = zapcore.NanosDurationEncoder
	case "string":
		encoderDuration = zapcore.StringDurationEncoder
	default:
		return nil, fmt.Errorf("unknown duration encoding %#v", encodingDuration)
	}

	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "level",
		TimeKey:        "timestamp",
		NameKey:        "logger",
		CallerKey:      "caller",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     encoderTime,
		EncodeDuration: encoderDuration,
	}

	switch strings.ToLower(encoding) {
	case "mixed", "":
		return NewMixedEncoder(encoderConfig), nil
	case "json":
		return zapcore.NewJSONEncoder(encoderConfig), nil
	case "console":
		return zapcore.NewConsoleEncoder(encoderConfig), nil
	default:
		return nil, fmt.Errorf("unknown encoding %#v", encoding)
	}
}

func (c *Config) encoderRsyslog(u *url.URL) (zapcore.Encoder, error) {
	encodingTime := u.Query().Get("encoding-time")
	if encodingTime == "" {
		encodingTime = c.EncodingTime
	}

	encodingDuration := u.Query().Get("encoding-duration")
	if encodingDuration == "" {
		encodingDuration = c.EncodingDuration
	}

	var encoderTime zapcore.TimeEncoder

	switch strings.ToLower(encodingTime) {
	case "millis":
		encoderTime = zapcore.EpochMillisTimeEncoder
	case "nanos":
		encoderTime = zapcore.EpochNanosTimeEncoder
	case "epoch":
		encoderTime = zapcore.EpochTimeEncoder
	case "iso8601", "":
		encoderTime = zapcore.ISO8601TimeEncoder
	default:
		return nil, fmt.Errorf("unknown time encoding %#v", encodingTime)
	}

	var encoderDuration zapcore.DurationEncoder
	switch strings.ToLower(encodingDuration) {
	case "seconds", "":
		encoderDuration = zapcore.SecondsDurationEncoder
	case "nanos":
		encoderDuration = zapcore.NanosDurationEncoder
	case "string":
		encoderDuration = zapcore.StringDurationEncoder
	default:
		return nil, fmt.Errorf("unknown duration encoding %#v", encodingDuration)
	}

	appName := u.Query().Get("app-name")
	if appName == "" {
		panic("app-name is required")
	}

	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		TimeKey:        "timestamp",
		NameKey:        "logger",
		CallerKey:      "caller",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     encoderTime,
		EncodeDuration: encoderDuration,
	}
	switch strings.ToLower(c.Type) {
	case "", "err":
		return NewRsyslogEncoder(encoderConfig, appName), nil
	case "access":
		return NewRsyslogAccessEncoder(encoderConfig, appName), nil
	default:
		return nil, fmt.Errorf("unknown rsyslog type encoding %#v", c.Type)
	}
}

func (c *Config) build(checkOnly bool) (*zap.Logger, error) {
	u, err := url.Parse(c.File)

	if err != nil {
		return nil, err
	}

	encoder, atomicLevel, err := c.encoder()
	if err != nil {
		return nil, err
	}

	if checkOnly {
		return nil, nil
	}

	if strings.ToLower(u.Path) == "none" {
		return zap.NewNop(), nil
	}

	ws, err := New(c.File)
	if err != nil {
		return nil, err
	}

	core := zapcore.NewCore(encoder, ws, atomicLevel)

	return zap.New(core), nil
}
