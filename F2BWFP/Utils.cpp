#include "stdafx.h"
#include "Utils.h"

using namespace F2B;
/*
// Convert WPF function result code to text
WCHAR * GetErrorTextOld(DWORD rc)
{
	switch (rc)
	{
	case ERROR_SUCCESS: return L"ERROR_SUCCESS: Success.";
	case FWP_E_CALLOUT_NOT_FOUND: return L"FWP_E_CALLOUT_NOT_FOUND: The callout does not exist.";
	case FWP_E_CONDITION_NOT_FOUND: return L"FWP_E_CONDITION_NOT_FOUND: The filter condition does not exist.";
	case FWP_E_FILTER_NOT_FOUND: return L"FWP_E_FILTER_NOT_FOUND: The filter does not exist.";
	case FWP_E_LAYER_NOT_FOUND: return L"FWP_E_LAYER_NOT_FOUND: The layer does not exist.";
	case FWP_E_PROVIDER_NOT_FOUND: return L"FWP_E_PROVIDER_NOT_FOUND: The provider does not exist.";
	case FWP_E_PROVIDER_CONTEXT_NOT_FOUND: return L"FWP_E_PROVIDER_CONTEXT_NOT_FOUND: The provider context does not exist.";
	case FWP_E_SUBLAYER_NOT_FOUND: return L"FWP_E_SUBLAYER_NOT_FOUND: The sub - layer does not exist.";
	case FWP_E_NOT_FOUND: return L"FWP_E_NOT_FOUND: The object does not exist.";
	case FWP_E_ALREADY_EXISTS: return L"FWP_E_ALREADY_EXISTS: An object with that GUID or LUID already exists.";
	case FWP_E_IN_USE: return L"FWP_E_IN_USE: The object is referenced by other objects, so it cannot be deleted.";
	case FWP_E_DYNAMIC_SESSION_IN_PROGRESS: return L"FWP_E_DYNAMIC_SESSION_IN_PROGRESS: The call is not allowed from within a dynamic session.";
	case FWP_E_WRONG_SESSION: return L"FWP_E_WRONG_SESSION: The call was made from the wrong session, so it cannot be completed.";
	case FWP_E_NO_TXN_IN_PROGRESS: return L"FWP_E_NO_TXN_IN_PROGRESS: The call must be made from within an explicit transaction.";
	case FWP_E_TXN_IN_PROGRESS: return L"FWP_E_TXN_IN_PROGRESS: The call is not allowed from within an explicit transaction.";
	case FWP_E_TXN_ABORTED: return L"FWP_E_TXN_ABORTED: The explicit transaction has been forcibly canceled.";
	case FWP_E_SESSION_ABORTED: return L"FWP_E_SESSION_ABORTED: The session has been canceled.";
	case FWP_E_INCOMPATIBLE_TXN: return L"FWP_E_INCOMPATIBLE_TXN: The call is not allowed from within a read - only transaction.";
	case FWP_E_TIMEOUT: return L"FWP_E_TIMEOUT: The call timed out while waiting to acquire the transaction lock.";
	case FWP_E_NET_EVENTS_DISABLED: return L"FWP_E_NET_EVENTS_DISABLED: The collection of network diagnostic events is disabled.";
	case FWP_E_INCOMPATIBLE_LAYER: return L"FWP_E_INCOMPATIBLE_LAYER: The operation is not supported by the specified layer.";
	case FWP_E_KM_CLIENTS_ONLY: return L"FWP_E_KM_CLIENTS_ONLY: The call is allowed for kernel - mode callers only.";
	case FWP_E_LIFETIME_MISMATCH: return L"FWP_E_LIFETIME_MISMATCH: The call tried to associate two objects with incompatible lifetimes.";
	case FWP_E_BUILTIN_OBJECT: return L"FWP_E_BUILTIN_OBJECT: The object is built - in, so it cannot be deleted.";
	case FWP_E_TOO_MANY_CALLOUTS: return L"FWP_E_TOO_MANY_CALLOUTS: The maximum number of callouts has been reached.";
	case FWP_E_NOTIFICATION_DROPPED: return L"FWP_E_NOTIFICATION_DROPPED: A notification could not be delivered because a message queue is at its maximum capacity.";
	case FWP_E_TRAFFIC_MISMATCH: return L"FWP_E_TRAFFIC_MISMATCH: The network traffic parameters do not match those for the security association context.";
	case FWP_E_INCOMPATIBLE_SA_STATE: return L"FWP_E_INCOMPATIBLE_SA_STATE: The call is not allowed for the current security association(SA) state.";
	case FWP_E_NULL_POINTER: return L"FWP_E_NULL_POINTER: A required pointer is null.";
	case FWP_E_INVALID_ENUMERATOR: return L"FWP_E_INVALID_ENUMERATOR: An enumerator value in a structure is out of range.";
	case FWP_E_INVALID_FLAGS: return L"FWP_E_INVALID_FLAGS: The flags field contains an invalid value.";
	case FWP_E_INVALID_NET_MASK: return L"FWP_E_INVALID_NET_MASK: A network mask is not valid.";
	case FWP_E_INVALID_RANGE: return L"FWP_E_INVALID_RANGE: An FWP_RANGE0 structure is not valid.";
	case FWP_E_INVALID_INTERVAL: return L"FWP_E_INVALID_INTERVAL: The time interval is not valid.";
	case FWP_E_ZERO_LENGTH_ARRAY: return L"FWP_E_ZERO_LENGTH_ARRAY: An array that must contain at least one element has zero length.";
	case FWP_E_NULL_DISPLAY_NAME: return L"FWP_E_NULL_DISPLAY_NAME: The displayData.name field cannot be null.";
	case FWP_E_INVALID_ACTION_TYPE: return L"FWP_E_INVALID_ACTION_TYPE: The action type is not one of the allowed action types for a filter.";
	case FWP_E_INVALID_WEIGHT: return L"FWP_E_INVALID_WEIGHT: The filter weight is not valid.";
	case FWP_E_MATCH_TYPE_MISMATCH: return L"FWP_E_MATCH_TYPE_MISMATCH: A filter condition contains a match type that is not compatible with the operands.";
	case FWP_E_TYPE_MISMATCH: return L"FWP_E_TYPE_MISMATCH: An FWP_VALUE0 structure or an FWPM_CONDITION_VALUE0 structure is of the wrong type.";
	case FWP_E_OUT_OF_BOUNDS: return L"FWP_E_OUT_OF_BOUNDS: An integer value is outside the allowed range.";
	case FWP_E_RESERVED: return L"FWP_E_RESERVED: A reserved field is nonzero.";
	case FWP_E_DUPLICATE_CONDITION: return L"FWP_E_DUPLICATE_CONDITION: A filter cannot contain multiple conditions operating on a single field.";
	case FWP_E_DUPLICATE_KEYMOD: return L"FWP_E_DUPLICATE_KEYMOD: A policy cannot contain the same keying module more than once.";
	case FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER: return L"FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER: The action type is not compatible with the layer.";
	case FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER: return L"FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER: The action type is not compatible with the sub - layer.";
	case FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER: return L"FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER: The raw context or the provider context is not compatible with the layer.";
	case FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT: return L"FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT: The raw context or the provider context is not compatible with the callout.";
	case FWP_E_INCOMPATIBLE_AUTH_METHOD: return L"FWP_E_INCOMPATIBLE_AUTH_METHOD: The authentication method is not compatible with the policy type.";
	case FWP_E_INCOMPATIBLE_DH_GROUP: return L"FWP_E_INCOMPATIBLE_DH_GROUP: The Diffie - Hellman group is not compatible with the policy type.";
	case FWP_E_EM_NOT_SUPPORTED: return L"FWP_E_EM_NOT_SUPPORTED: An IKE policy cannot contain an Extended Mode policy.";
	case FWP_E_NEVER_MATCH: return L"FWP_E_NEVER_MATCH: The enumeration template or subscription will never match any objects.";
	case FWP_E_PROVIDER_CONTEXT_MISMATCH: return L"FWP_E_PROVIDER_CONTEXT_MISMATCH: The provider context is of the wrong type.";
	case FWP_E_INVALID_PARAMETER: return L"FWP_E_INVALID_PARAMETER: The parameter is incorrect.";
	case FWP_E_TOO_MANY_SUBLAYERS: return L"FWP_E_TOO_MANY_SUBLAYERS: The maximum number of sublayers has been reached.";
	case FWP_E_CALLOUT_NOTIFICATION_FAILED: return L"FWP_E_CALLOUT_NOTIFICATION_FAILED: The notification function for a callout returned an error.";
	case FWP_E_INVALID_AUTH_TRANSFORM: return L"FWP_E_INVALID_AUTH_TRANSFORM: The IPsec authentication transform is not valid.";
	case FWP_E_INVALID_CIPHER_TRANSFORM: return L"FWP_E_INVALID_CIPHER_TRANSFORM: The IPsec cipher transform is not valid.";
	}

	// in case of communication with remote machine, WFP functions
	// can receive also RPC error messages
	//static WCHAR unknown[sizeof(WCHAR)*(26 + 10)];
	//swprintf_s(unknown, 36, L"Unrecognized WFP_ERROR 0x%x.", rc);
	//return unknown;

	static WCHAR unknown[1024];
	LPTSTR lpMsgBuf = NULL;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		rc,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
		);

	lpMsgBuf[wcslen(lpMsgBuf) - 1] = '\0'; // remove new line character
	swprintf(unknown, 1024, L"Unrecognized WFP_ERROR 0x%x (%s)", rc, lpMsgBuf);

	LocalFree(lpMsgBuf);

	return unknown;
}


// Format WPF error message
WCHAR * FormatErrorText(WCHAR * msg, DWORD rc)
{
	static WCHAR buf[1024];
	swprintf_s(buf, 1023, L"%s (%s)", msg, GetErrorText(rc));
	return buf;
}


String^ GetErrorText(DWORD rc)
{
	return gcnew String(GetErrorTextOld(rc));
}
*/
