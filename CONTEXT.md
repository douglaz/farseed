# Farseed

Farseed is a page that lets an operator rent a machine from a provider and set it up, keeping its own record of what was approved and bought.

## Language

### Buying a machine

**Approval**:
The operator's yes to buying one machine at stated terms. One **Approval** is one intent to buy; approving again after a refusal is a new **Approval**.
_Avoid_: Confirmation, purchase intent

**Order ID**:
The identifier made for one **Approval** and saved before anything is sent to the provider. Each **Approval** has exactly one **Order ID**, and re-sending that **Approval** reuses it.
_Avoid_: Ticket number, idempotency key, request ID

**Order**:
The provider's record of one machine being bought. A provider that honours **Order IDs** holds at most one **Order** per **Order ID**.
_Avoid_: Purchase (for the provider's record), invoice

**Uncertain purchase**:
An **Approval** whose **Order** was sent and whose reply never arrived, so the page cannot tell whether an **Order** exists.
_Avoid_: Failed purchase, pending order

**Honouring provider**:
A provider that has told the page it holds at most one **Order** per **Order ID**. Only an **Uncertain purchase** made with a **Honouring provider** may be sent again.

## Example dialogue

> **Dev:** The provider refused for a missing email. The operator adds one and approves again. Same **Order ID**?
> **Operator:** No. That is a second **Approval**, so it gets a new **Order ID**. The first one never became an **Order**.
> **Dev:** And if the reply to the second one is lost?
> **Operator:** Then it is an **Uncertain purchase**. With a **Honouring provider** the page sends it again under the same **Order ID** and gets the original **Order** back. With any other provider it checks what exists and asks me.

## Flagged ambiguities

- "Ticket number" was used in conversation for the **Order ID**. Resolved: **Order ID** is the only name.
- "Purchase" was used both for the operator's side and the provider's record. Resolved: the provider's record is an **Order**; "purchase" stays only in **Uncertain purchase**.
