package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

var atomicLevel = zap.NewAtomicLevel()

func SetLogLevel(l string) {
	switch l {
	case "debug":
		atomicLevel.SetLevel(zapcore.DebugLevel)
	case "error":
		atomicLevel.SetLevel(zapcore.ErrorLevel)
	case "fatal":
		atomicLevel.SetLevel(zapcore.FatalLevel)
	case "warn":
		atomicLevel.SetLevel(zapcore.WarnLevel)
	default:
		atomicLevel.SetLevel(zapcore.InfoLevel)
	}
}

func InitLogger() *zap.Logger {

	config := zap.Config{
		Level:       atomicLevel,
		Development: true,
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "msg",
			LevelKey:     "level",
			TimeKey:      "time",
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			EncodeLevel:  zapcore.LowercaseLevelEncoder,
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	logger, err := config.Build()
	if err != nil {
		logger.Fatal("cannot create logger", zap.Error(err))
		os.Exit(1)
	}
	defer logger.Sync()
	return logger
}
