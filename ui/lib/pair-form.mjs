// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// The one manual-pairing form, used by app.mjs's shell-level "waiting for
// Helm" state and by Operate's §13.4 collapsed "Advanced: pair this tab by
// hand" escape hatch — the spec asks for the second to reuse the first
// rather than growing its own copy.
import { saveToken, savePort, loadPort } from "../api.mjs";

export function pairFormHtml() {
  return `
    <form class="token-form" aria-label="Pair with helmd">
      <label for="token-input">Pairing token</label>
      <input id="token-input" name="token" type="password" autocomplete="off" placeholder="paste token or open the CLI pairing link" />
      <label for="port-input">Port</label>
      <input id="port-input" name="port" type="number" min="1" max="65535" value="${loadPort()}" style="width:6rem" />
      <button type="submit">Pair</button>
    </form>`;
}

export function wirePairForm(root, onPaired) {
  root.querySelector("form.token-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const token = root.querySelector("#token-input").value.trim();
    const port = Number(root.querySelector("#port-input").value) || loadPort();
    savePort(port);
    if (token) {
      saveToken(token);
      onPaired();
    }
  });
}
