export type Band = "high" | "suspicious" | "low" | "cant_assess";

export interface RuleWarning {
  rule_id: string;
  severity: string;
  message: string;
}

export interface AnalysisResult {
  band: Band;
  headline: string;
  advice: string;
  footer: string;
  display_host: string;
  model_reasons: string[];
  rule_warnings: RuleWarning[];
}

export interface LinkResult {
  display_host: string;
  band: Band;
  headline: string;
  lookalike: boolean;
  rule_warnings: RuleWarning[];
}

export interface EmailResult {
  band: Band;
  headline: string;
  advice: string;
  footer: string;
  sender: string;
  model_reasons: string[];
  rule_warnings: RuleWarning[];
  links: LinkResult[];
  links_checked: boolean;
  truncated: boolean;
  header_checks: { available: boolean; message: string; warnings: RuleWarning[] };
  model_note: string;
}

export interface Account {
  email: string;
  csrf_token: string;
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrfToken = "";

export function setCsrfToken(token: string) {
  csrfToken = token;
}

async function request<T>(path: string, method: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const isForm = body instanceof FormData;
  // A FormData body needs the browser to set its own multipart Content-Type.
  if (body !== undefined && !isForm) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
  });
  if (!response.ok) {
    let message = "Something went wrong. Please try again.";
    try {
      const data = await response.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (response.status === 422) message = "Please check what you entered.";
    } catch {
      // keep the generic message
    }
    throw new ApiError(response.status, message);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export const api = {
  me: () => request<Account>("/api/me", "GET"),
  register: (email: string, password: string, consent: boolean) =>
    request<Account>("/api/auth/register", "POST", { email, password, consent }),
  login: (email: string, password: string) =>
    request<Account>("/api/auth/login", "POST", { email, password }),
  logout: () => request<void>("/api/auth/logout", "POST"),
  analyzeUrl: (url: string) => request<AnalysisResult>("/api/analyze/url", "POST", { url }),
  analyzeEmailFields: (subject: string, sender: string, body: string) =>
    request<EmailResult>("/api/analyze/email", "POST", { mode: "fields", subject, sender, body }),
  analyzeEmailSource: (source: string) =>
    request<EmailResult>("/api/analyze/email", "POST", { mode: "raw", source }),
  analyzeEmailFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<EmailResult>("/api/analyze/email/upload", "POST", form);
  },
};
