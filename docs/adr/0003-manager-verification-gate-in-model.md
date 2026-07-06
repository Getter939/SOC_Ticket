# Manager-verification gate is enforced in the model, not only the view

Whether a contained Ticket must be verified by the SOC Manager before it can close is decided deterministically inside `Ticket.transition_to` / `can_transition_to` (via `requires_manager_verification`), which raises on the illegal edge. The view layer also reflects the rule in the UI, but the model is the authoritative gate.

Chosen for defense in depth: the close/approve transitions are security-critical, and enforcing the routing rule in the state machine makes it "view-proof" — it holds no matter which view, management command, or future API path drives the transition. The trade-off is that the rule (severity floor OR emergency flag) lives in the model rather than a more visible policy/config layer, so a reader looking only at the views will not see why an APPROVED transition was rejected. Recorded here so the model-level gate is not mistaken for redundant validation and removed.
