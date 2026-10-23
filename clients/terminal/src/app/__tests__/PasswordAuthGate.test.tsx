import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
vi.mock("next-auth/react", () => ({ signIn: vi.fn() }));
import { AuthGate } from "../AuthGate";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it("renders email/password instead of test login and submits both fields", async () => {
  const fetcher = vi.fn(async (url: string) => {
    if (url === "/api/auth/me") return new Response("{}", { status: 401 });
    if (url === "/api/auth/instance") return new Response(JSON.stringify({ admin_exists: true, password_auth: true }));
    if (url === "/api/auth/providers") return new Response("{}");
    return new Response(JSON.stringify({ error: "Invalid email or password" }), { status: 401 });
  });
  vi.stubGlobal("fetch", fetcher);
  render(<AuthGate><div>Workbench</div></AuthGate>);
  const password = await screen.findByLabelText("Password");
  expect(screen.queryByText(/debug login/i)).toBeNull();
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "kevin@example.com" } });
  fireEvent.change(password, { target: { value: "Synthetic-fixture-only-123!" } });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledWith("/api/auth/login", expect.objectContaining({ body: JSON.stringify({ email: "kevin@example.com", password: "Synthetic-fixture-only-123!" }) })));
  expect(await screen.findByText("Invalid email or password")).toBeTruthy();
});
