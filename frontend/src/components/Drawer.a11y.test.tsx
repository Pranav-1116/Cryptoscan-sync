/* Accessibility (audit 06): the drawer is a modal dialog — focus enters on
 * open, Tab is trapped inside, Escape closes, focus returns on close. */

import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";
import { Drawer } from "./ui";

describe("Drawer accessibility", () => {
  it("exposes dialog semantics and takes focus on open", () => {
    render(<Drawer title="Asset detail" onClose={() => {}}><button>inside</button></Drawer>);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-label", "Asset detail");
    expect(document.activeElement).toBe(dialog);
  });

  it("traps Tab inside the drawer and closes on Escape", () => {
    const onClose = vi.fn();
    render(
      <div>
        <button>behind</button>
        <Drawer title="Detail" onClose={onClose}>
          <button>first</button>
          <button>last</button>
        </Drawer>
      </div>,
    );
    const dialog = screen.getByRole("dialog");
    // focus the last control, then Tab wraps to the drawer's FIRST focusable
    // (the Close button) — never to "behind" outside the dialog
    (screen.getByText("last") as HTMLElement).focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));
    // shift-Tab from the first wraps back to the last
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(screen.getByText("last"));
    // Escape closes
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });
});
