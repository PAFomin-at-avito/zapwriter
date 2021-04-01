package zapwriter

import (
	"fmt"
	"os"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

type RsyslogEncoder struct {
	*jsonEncoder

	appName  string
	hostname string
}

func NewRsyslogEncoder(cfg zapcore.EncoderConfig, appName string) zapcore.Encoder {
	inner := newJSONEncoder(cfg, false)

	hostname, err := os.Hostname()
	if err != nil {
		panic(fmt.Errorf("could not get hostname: %s", err.Error()))
	}

	return RsyslogEncoder{
		jsonEncoder: inner,
		appName:     appName,
		hostname:    hostname,
	}
}

func (enc RsyslogEncoder) Clone() zapcore.Encoder {
	return RsyslogEncoder{
		jsonEncoder: enc.jsonEncoder.Clone().(*jsonEncoder),
		appName:     enc.appName,
		hostname:    enc.hostname,
	}
}

func (enc RsyslogEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	finalFields := make([]zapcore.Field, 0, len(fields))
	var component string = ent.LoggerName
	var contextID int64 = 0
	for _, field := range fields {
		switch field.Key {
		case "component":
			component = field.String
		case "contextID", "context_id":
			contextID = field.Integer
		default:
			finalFields = append(finalFields, field)
		}
	}
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
	final.AddString("component", component)
	final.AddInt64("context_id", contextID)
	final.AddString("event_datetime", eventDatetimeISO)
	final.AddString("event_date", eventDatetimeISO[:10])
	final.AddString("msg", ent.Message)

	if enc.LevelKey != "" && enc.EncodeLevel != nil {
		final.addKey("level")
		enc.EncodeLevel(ent.Level, final)
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
