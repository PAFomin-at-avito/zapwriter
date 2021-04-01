package zapwriter

import (
	"fmt"
	"math"
	"os"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

type RsyslogAccessEncoder struct {
	*jsonEncoder

	appName  string
	hostname string
}

func NewRsyslogAccessEncoder(cfg zapcore.EncoderConfig, appName string) zapcore.Encoder {
	inner := newJSONEncoder(cfg, false)

	hostname, err := os.Hostname()
	if err != nil {
		panic(fmt.Errorf("could not get hostname: %s", err.Error()))
	}

	return RsyslogAccessEncoder{
		jsonEncoder: inner,
		appName:     appName,
		hostname:    hostname,
	}
}

func (enc RsyslogAccessEncoder) Clone() zapcore.Encoder {
	return RsyslogAccessEncoder{
		jsonEncoder: enc.jsonEncoder.Clone().(*jsonEncoder),
		appName:     enc.appName,
		hostname:    enc.hostname,
	}
}

func (enc RsyslogAccessEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	eventDatetimeISO := ent.Time.Format("2006-01-02T15:04:05.000000")
	eventDatetimeSyslog := ent.Time.Format("Jan 02 15:04:05")

	final := enc.clone()
	extra := enc.clone()
	extra.buf.Write(enc.buf.Bytes())

	wr := getDirectWriteEncoder()
	wr.buf = final.buf

	wr.AppendString(eventDatetimeSyslog)
	final.buf.AppendByte(' ')

	wr.AppendString(enc.hostname)
	final.buf.AppendByte(' ')

	wr.AppendString(enc.appName)
	final.buf.AppendByte(':')
	final.buf.AppendByte(' ')

	putDirectWriteEncoder(wr)

	final.buf.AppendByte('{')
	final.AddString("event_datetime", eventDatetimeISO)
	final.AddString("event_date", eventDatetimeISO[:10])
	final.AddString("msg", ent.Message)
	final.AddString("hostname", enc.hostname)
	final.AddString("component", ent.LoggerName)

	if enc.LevelKey != "" && enc.EncodeLevel != nil {
		final.addKey("level")
		enc.EncodeLevel(ent.Level, final)
	}

	finalFields := make([]zapcore.Field, 0, len(fields))
	for _, field := range fields {
		switch field.Key {
		case "handler", "carbonapi_uuid", "peer_ip":
			// String
			final.AddString(field.Key, field.String)
		case "targets", "metrics":
			// Strings
			// TODO: handle error
			_ = final.AddArray(field.Key, field.Interface.(zapcore.ArrayMarshaler))
		case "runtime":
			// Float64
			final.AddFloat64(field.Key, math.Float64frombits(uint64(field.Integer)))
		case "http_code", "from", "until":
			// Int32
			final.AddInt32(field.Key, int32(field.Integer))
		default:
			finalFields = append(finalFields, field)
		}
	}

	if ent.Caller.Defined && enc.CallerKey != "" && enc.EncodeCaller != nil {
		extra.addKey("caller")
		enc.EncodeCaller(ent.Caller, extra)
	}
	if ent.Stack != "" && enc.StacktraceKey != "" {
		extra.AddString(enc.StacktraceKey, ent.Stack)
	}

	addFields(extra, finalFields)
	final.AddString("extra", "{"+extra.buf.String()+"}")
	final.closeOpenNamespaces()

	final.buf.AppendByte('}')
	final.buf.AppendByte('\n')

	ret := final.buf
	return ret, nil
}
