---
status: accepted
---

# An uncertain purchase is sent again only to a honouring provider

When the reply to an approved purchase is lost, the page cannot tell whether the provider created an order. Every approval carries an order ID, and a provider that honours order IDs answers a repeat with the original order, so sending again is safe there. We decided the page sends an uncertain purchase again only when the provider has told the page it honours order IDs; with any other provider it checks what exists and asks the operator, as it did before order IDs existed.

## Considered options

- **Always send again.** Fewest interruptions, but a provider that ignores the order ID creates a second order and a second invoice, which is the fault the order ID exists to prevent.
- **Never send again.** Safe everywhere, but the operator is still asked after every lost reply, even where the provider could have answered.

## Consequences

- The page saves the order ID before the first send for every provider, so stores are ready on the day a provider starts honouring it.
- A provider must say that it honours order IDs; silence means it does not. Support is never inferred from the provider's name or address.
- A re-approval after a refusal is a new approval with a new order ID, so it is never treated as a repeat.
