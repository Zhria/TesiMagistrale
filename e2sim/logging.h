#ifndef E2SIM_LOGGING_H
#define E2SIM_LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
  LOG_LEVEL_TRACE = 0,
  LOG_LEVEL_DEBUG = 1,
  LOG_LEVEL_INFO  = 2,
  LOG_LEVEL_WARN  = 3,
  LOG_LEVEL_ERROR = 4,
  LOG_LEVEL_FATAL = 5,
};

// Initializes log routing (file/console) using the same YAML config passed to the binary.
// If config_path is null or parsing fails, sensible defaults are used.
void logln_init_from_yaml(const char* config_path);

// Writes one log line at the given level.
// Routing rules:
// - level < consoleLevel  -> file
// - level >= consoleLevel -> console
// - if teeHighToFile=true, level >= consoleLevel is also appended to file
void logln_level(int level, const char* fmt, ...);

#ifdef __cplusplus
} // extern "C"
#endif

#ifndef LOG_T
#define LOG_T(...) do { logln_level(LOG_LEVEL_TRACE, __VA_ARGS__); } while (0);
#endif
#ifndef LOG_D
#define LOG_D(...) do { logln_level(LOG_LEVEL_DEBUG, __VA_ARGS__); } while (0);
#endif
#ifndef LOG_I
#define LOG_I(...) do { logln_level(LOG_LEVEL_INFO,  __VA_ARGS__); } while (0);
#endif
#ifndef LOG_W
#define LOG_W(...) do { logln_level(LOG_LEVEL_WARN,  __VA_ARGS__); } while (0);
#endif
#ifndef LOG_E
#define LOG_E(...) do { logln_level(LOG_LEVEL_ERROR, __VA_ARGS__); } while (0);
#endif
#ifndef LOG_F
#define LOG_F(...) do { logln_level(LOG_LEVEL_FATAL, __VA_ARGS__); } while (0);
#endif

#endif // E2SIM_LOGGING_H
