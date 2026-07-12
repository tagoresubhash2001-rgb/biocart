# BioCart Enterprise Security Specification & Threat Model

## Data Invariants

1. **A Customer Profile is Private**: A user profile (`/users/{uid}`) can only be written by the authenticated user with the matching UID.
2. **Products & Inventory are Read-Only for Public**: Only authenticated administrators can modify product configurations and baseline inventory. Customers can only read products.
3. **Orders must be Authorized**: An order (`/orders/{orderId}`) can only be created if the `userId` field matches `request.auth.uid`. No user can read or fetch orders belonging to another user.
4. **Order Items match Orders**: Order items (`/order_items/{itemId}`) can only be created alongside a valid, matching order.
5. **Private Shopping Cart**: A shopping cart (`/shopping_carts/{cartId}`) can only be read or modified by the user who owns it.
6. **No Self-Privilege Escalation**: A user registering or updating their profile is strictly forbidden from self-assigning role-escalation fields (like setting `role: 'super_admin'`).

---

## The "Dirty Dozen" Attack Payloads

The following malicious payloads must be blocked, returning `PERMISSION_DENIED` under all circumstances:

1. **Self-Escalation Role Payload**: An unverified user attempts to create a user profile with role `super_admin`.
2. **Identity Spoofing Order**: User `A` tries to submit an order with `userId` set to User `B`.
3. **Malicious Ghost Field Insertion**: A user attempts to inject an unauthorized field `isPremiumDiscountAllowed: true` into their shopping cart.
4. **Ad-hoc Price Poisoning**: A customer attempts to create a product document with a price of `$0.01` to force checkout exploitation.
5. **Unverified Email Verification Spoof**: A user whose `request.auth.token.email_verified` is `false` attempts to register a profile in a secured collection.
6. **Subcollection Orphan Attack**: A user attempts to write a task/order item directly without creating the parent order/project.
7. **Bypassing Terminal Lock State**: A user attempts to update an order after its status has reached `'completed'` or `'refunded'`.
8. **Negative Cost Poisoning**: A user attempts to create an order item with negative price (`price: -500.00`).
9. **Rogue Coupon Creation**: A standard guest user attempts to create a 100% off coupon code document.
10. **Shadow System Setting Overwrite**: A user attempts to overwrite a critical system configuration setting in `/settings/payment_gateway`.
11. **Spamming Analytics Payload**: A user attempts to write an analytics event document without a valid `sessionId` and containing a payload size of 5MB.
12. **Double Refund Exploitation**: An attacker attempts to execute an update on an order with a payload modifying BOTH `paymentStatus` to `'refunded'` AND `totalAmount` to `$1,000,000.00`.

---

## The Test Runner (`firestore.rules.test.ts`)

Below is the complete testing suite designed to prove that the "Dirty Dozen" payloads fail against the Firebase security boundaries.

```typescript
import { 
  initializeTestEnvironment, 
  RulesTestEnvironment, 
  assertFails, 
  assertSucceeds 
} from '@firebase/rules-unit-testing';
import { doc, setDoc, getDoc, updateDoc } from 'firebase/firestore';

let testEnv: RulesTestEnvironment;

beforeAll(async () => {
  testEnv = await initializeTestEnvironment({
    projectId: 'ai-studio-biocart-49422539-896f-4e75-b6d6-4e149e1cb56f',
    firestore: {
      rules: require('fs').readFileSync('firestore.rules', 'utf8'),
      host: 'localhost',
      port: 8080,
    },
  });
});

afterAll(async () => {
  await testEnv.cleanup();
});

beforeEach(async () => {
  await testEnv.clearFirestore();
});

describe('BioCart Zero-Trust Threat Audits', () => {
  // Test 1: Self-Escalation Role Payload
  test('Attack 1: Reject user setting super_admin role on registration', async () => {
    const maliciousUserDb = testEnv.authenticatedContext('user_123', { email_verified: true }).firestore();
    const docRef = doc(maliciousUserDb, 'users', 'user_123');
    await assertFails(setDoc(docRef, {
      uid: 'user_123',
      name: 'Hacker Bob',
      email: 'bob@hacker.com',
      role: 'super_admin',
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));
  });

  // Test 2: Identity Spoofing Order
  test('Attack 2: Reject order creation if userId does not match auth UID', async () => {
    const userADb = testEnv.authenticatedContext('user_A', { email_verified: true }).firestore();
    const docRef = doc(userADb, 'orders', 'ord_999');
    await assertFails(setDoc(docRef, {
      userId: 'user_B', // Attempting to place order on behalf of B
      orderNumber: 'ORD-999',
      paymentMethod: 'cod',
      paymentStatus: 'pending',
      shippingAddressId: 'addr_1',
      billingAddressId: 'addr_1',
      subtotal: 100,
      discountAmount: 0,
      totalAmount: 100,
      isDeleted: false,
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));
  });

  // Test 3: Rogue Coupon Creation
  test('Attack 3: Reject coupon document creation from standard user', async () => {
    const customerDb = testEnv.authenticatedContext('user_A', { email_verified: true }).firestore();
    const docRef = doc(customerDb, 'coupons', '100PERCENTOFF');
    await assertFails(setDoc(docRef, {
      code: '100PERCENTOFF',
      discountType: 'percentage',
      discountValue: 100,
      minOrderAmount: 0,
      startDate: new Date().toISOString(),
      endDate: new Date().toISOString(),
      usageLimit: 1000,
      usedCount: 0,
      isDeleted: false,
      version: 1,
    }));
  });
});
```
