"use strict";

class CheckError extends Error {
  constructor(code) {
    super(code);
    this.name = "CheckError";
    this.code = code;
  }
}

module.exports = { CheckError };
