# ReTab

If you’ve used Burp Repeater for more than a few minutes, you know the problem.

You send a bunch of requests, and suddenly your tabs are named `1`, `2`, `3` … or just the same hostname over and over. After 10 tabs, you’re clicking through each one trying to remember which was the login request. After 50 tabs, it’s complete mess.

This extension names your Repeater tabs so you do not have to.


Right-click any request and choose **Send to Repeater (ReTab)**.
The new tab will have a clear, readable name based on what the request actually does.

Instead of:

`1`, `2`, `3`, `4`
<img width="1436" height="765" alt="image" src="https://github.com/user-attachments/assets/2b60c222-f98a-46a6-bacb-1c63b147c620" />


You get:

`POST-/api/v2/auth/login`, `GET-GetAccountDetails`, `POST-/profile/{id}`
<img width="1434" height="739" alt="image" src="https://github.com/user-attachments/assets/4c844b3a-94e6-4f72-b93c-4972e675a06f" />


It just gives your Repeater tabs useful names.

---

## How It Chooses the Name

The extension checks the request and picks the best possible name using this order:

---

### 1) REST (Everything Else)

For normal API requests, it uses:

* The HTTP method
* The cleaned URL path

It can also normalize numeric IDs, UUIDs, and long hex strings to `{id}` so your tabs don’t fill up with random numbers.

Examples:

```
GET-/api/users/{id}
POST-/api/auth/login
DELETE-/api/orders/{id}
PUT-/api/settings[form]
POST-/api/upload[multi]
```

---

### 2) GraphQL

GraphQL is detected if:

* The URL contains `graphql`
* The query string contains `query=`
* The JSON body contains `"query"`

The extension tries to extract the operation name in this order:

1. `operationName` field in JSON
2. Operation name from the query (`query GetUser { ... }` → `GetUser`)
3. Apollo persisted query hash (first 6 characters → `gql-a3f2b1`)
4. If nothing is found → falls back to `graphql`

Works with:

* POST JSON GraphQL
* GET with URL-encoded query
* Apollo persisted queries

Examples:

```
POST-GetUserProfile
POST-CreateOrder
POST-gql-a3f2b1

```
---

### 3) SOAP / XML

If the `Content-Type` contains `xml`, the extension looks at the XML body and extracts the main action name.

It skips common SOAP wrapper tags like `Envelope`, `Header`, and `Body`.

Examples:

```
SOAP-GetAccountDetails
SOAP-TransferFunds
SOAP-request
```
---


### 4) WebSocket

If the request contains `Upgrade: websocket`, the tab name starts with `WS-` followed by the path.

Examples:

```
WS-/ws/chat
WS-/notifications
```
---

## Extra Features

### Method Override Support

If the request includes:

```
X-HTTP-Method-Override
```

The extension uses that method instead of the original one.

---

### Content-Type Tags

To help you tell requests apart, the extension adds small tags:

* `[form]` for URL-encoded bodies
* `[multi]` for multipart/form-data

So you can easily see the difference between JSON and form submissions to the same endpoint.

---

### Auth Context Hints

When enabled, the tab name can include a short hint from the authentication context.

Examples:

```
GET-/api/admin/users[..x9f2]   ← last 4 chars of Bearer token
POST-/api/settings[admin]     ← username from Basic auth
```

This helps when testing the same endpoint with different users.

---

### Smart Truncation

Very long paths are shortened by collapsing the middle and keeping the important last part.

Example:

```
GET-/api/v2/organizations/.../invoices
```

Usually, the end of the path matters more than the middle.

---

### Duplicate Handling

If two requests would create the same tab name, a number is added automatically.

```
POST-/api/users
POST-/api/users (2)
POST-/api/users (3)
```

---

## Settings Tab

A new tab called **ReTab** appears inside Burp.

You can change settings using simple checkboxes — no need to edit the code.

| Setting                    | What it does                                        |
| -------------------------- | --------------------------------------------------- |
| Include HTTP method prefix | Adds `POST-`, `GET-`, etc.                          |
| Append query string        | Adds part of the query string                       |
| Normalize IDs              | Replaces numeric IDs, UUIDs, hex values with `{id}` |
| Auth context hint          | Adds token or username hint                         |
| Max name length            | Sets character limit for tab names                  |

Changes apply immediately. No restart needed.

---

## Installation

1. Download `ReTab.py`
2. Open Burp Suite
3. Go to **Extender → Options**
4. Set the path to your Jython standalone JAR
5. Go to **Extender → Extensions → Add**
6. Choose **Python**
7. Select the file
8. Click **Next**

You should now see a **ReTab** tab in Burp.

---

## How to Use

1. Find any request in Proxy, Target, etc.
2. Right-click it
3. Click **Send to Repeater (ReTab)**
4. The request opens in Repeater with a clear tab name

That’s it.

---

## Limitations

* It does not rename tabs sent using Burp’s default “Send to Repeater”. Only tabs sent through its own context menu are renamed.
* It does not handle gRPC-Web, Server-Sent Events, or other uncommon protocols.
* Basic auth username extraction assumes valid Base64. If decoding fails, it skips the hint.
* The duplicate counter resets after 5000 unique names to prevent memory growth.

---

## Disclaimer

This extension was built with Claude Opus 4.6.

There is no license attached. You can use it, modify it, share it, or rewrite it however you want. No credit required.

If it breaks something, that’s on you.
If it saves you time, I’m glad it helped.
