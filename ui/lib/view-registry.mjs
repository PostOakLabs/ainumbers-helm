// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX2-B-TABMETA (§12): VIEWS maps a tab id to its render function. Split
// out of app.mjs so the §12.5 gate test can import it without also importing
// app.mjs's unconditional boot() (which needs `document` and isn't safe to
// evaluate under node:test).
import { renderHome } from "../views/home.mjs";
import { renderAgents } from "../views/agents.mjs";
import { renderChoose } from "../views/choose.mjs";
import { renderCanvas } from "../views/canvas.mjs";
import { renderConnect } from "../views/connect.mjs";
import { renderRun } from "../views/run.mjs";
import { renderOperate } from "../views/operate.mjs";
import { renderVerify } from "../views/verify.mjs";
import { renderReview } from "../views/review.mjs";
import { renderLearn } from "../views/learn.mjs";
import { renderRegister } from "../views/register.mjs";
import { renderDeadlines } from "../views/deadlines.mjs";

export const VIEWS = { home: renderHome, choose: renderChoose, canvas: renderCanvas, connect: renderConnect, run: renderRun, verify: renderVerify, review: renderReview, operate: renderOperate, register: renderRegister, deadlines: renderDeadlines, learn: renderLearn, agents: renderAgents };
