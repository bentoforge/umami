// Browser WebAuthn helpers: convert the server's base64url challenge JSON to/from the ArrayBuffers
// that `navigator.credentials` requires. The server (webauthn-rs) emits/consumes standard WebAuthn
// JSON with base64url-encoded binary fields.

/** Decodes a base64url string to an ArrayBuffer. */
export function b64urlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** Encodes an ArrayBuffer as a base64url string (no padding). */
export function bufferToB64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] as number);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface DescriptorJSON {
  id: string;
  type: string;
  transports?: string[];
}

/** Turns the server's `publicKey` creation options into browser `PublicKeyCredentialCreationOptions`. */
export function toCreationOptions(publicKey: any): PublicKeyCredentialCreationOptions {
  return {
    ...publicKey,
    challenge: b64urlToBuffer(publicKey.challenge),
    user: { ...publicKey.user, id: b64urlToBuffer(publicKey.user.id) },
    excludeCredentials: (publicKey.excludeCredentials ?? []).map((c: DescriptorJSON) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    })),
  } as PublicKeyCredentialCreationOptions;
}

/** Turns the server's `publicKey` request options into browser `PublicKeyCredentialRequestOptions`. */
export function toRequestOptions(publicKey: any): PublicKeyCredentialRequestOptions {
  return {
    ...publicKey,
    challenge: b64urlToBuffer(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials ?? []).map((c: DescriptorJSON) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    })),
  } as PublicKeyCredentialRequestOptions;
}

/** Serializes a registration credential into the JSON the server's `register/finish` expects. */
export function registrationToJSON(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToB64url(response.attestationObject),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
    },
    extensions: credential.getClientExtensionResults(),
  };
}

/** Serializes an assertion credential into the JSON the server's `login/finish` expects. */
export function assertionToJSON(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToB64url(response.authenticatorData),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      signature: bufferToB64url(response.signature),
      userHandle: response.userHandle ? bufferToB64url(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}
