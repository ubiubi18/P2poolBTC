"use strict";
globalThis.history.replaceState({}, "", "/callback");
globalThis.setTimeout(() => globalThis.location.replace("/"), 700);
