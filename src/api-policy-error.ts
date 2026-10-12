/** Internal fixed diagnostics shared by policy adapters. */
export class ApiPolicyError extends Error {
  readonly code: string;
  location = "policy";

  constructor(code: string, message: string) {
    super(message);
    this.name = "ApiPolicyError";
    this.code = code;
  }
}

