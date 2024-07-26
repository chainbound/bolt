export type LogLevel = "info" | "debug" | "error" | "warn" | "success" | "none";

export default class Logger {
  constructor(private logLevel: LogLevel, private namespace: string) {}

  private log(message: string, level: LogLevel, color: Colors) {
    if (this.logLevel !== "none") {
      console.log(
        color,
        `[${
          this.namespace
        }] [${new Date().toLocaleString()}] [${level}] ${message}`,
        Colors.Reset
      );
    }
  }

  public info(message: string) {
    this.log(message, "info", Colors.Blue);
  }

  public debug(message: string) {
    this.log(message, "debug", Colors.Dim);
  }

  public error(message: string) {
    this.log(message, "error", Colors.Red);
  }

  public warn(message: string) {
    this.log(message, "warn", Colors.Yellow);
  }

  public success(message: string) {
    this.log(message, "success", Colors.Green);
  }
}

enum Colors {
  Black = "\x1b[30m",
  Red = "\x1b[31m",
  Green = "\x1b[32m",
  Yellow = "\x1b[33m",
  Blue = "\x1b[34m",
  Magenta = "\x1b[35m",
  Cyan = "\x1b[36m",
  White = "\x1b[37m",
  Gray = "\x1b[90m",

  Reset = "\x1b[0m",
  Bright = "\x1b[1m",
  Dim = "\x1b[2m",
  Underscore = "\x1b[4m",
  Blink = "\x1b[5m",
  Reverse = "\x1b[7m",
  Hidden = "\x1b[8m",
}

export const logger = new Logger(
  (process.env.LOG_LEVEL as LogLevel) || "info",
  "BOLT"
);
