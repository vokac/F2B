#pragma once
#include <initguid.h>
#include <aclapi.h>
#include <fwpmu.h>
#include <stdio.h> // wsprintf
#include <vcclr.h> // PtrToStringChars
#include <sddl.h> // REMOVE only for test ConvertSecurityDescriptorToStringSecurityDescriptor

#include <vector>

using namespace System;
using namespace System::Net;
using namespace System::Net::Sockets;
using namespace System::Threading;
using namespace System::Collections;
using namespace System::Collections::Generic;
using namespace System::Security::Principal;

namespace F2B {

	// {06B4DF79-CA7B-4F43-B8E2-F3B193330BB8}
	DEFINE_GUID(F2BFW_SESSION_KEY,
		0x6b4df79, 0xca7b, 0x4f43, 0xb8, 0xe2, 0xf3, 0xb1, 0x93, 0x33, 0xb, 0xb8);
	// {AEBBA4B7-7D2F-436F-B0ED-40069FB63CBC}
	DEFINE_GUID(F2BFW_PROVIDER_KEY,
		0xaebba4b7, 0x7d2f, 0x436f, 0xb0, 0xed, 0x40, 0x6, 0x9f, 0xb6, 0x3c, 0xbc);
	// {82FF6293-AF12-4EF8-97DD-FD5477303838}
	DEFINE_GUID(F2BFW_SUBLAYER_KEY,
		0x82ff6293, 0xaf12, 0x4ef8, 0x97, 0xdd, 0xfd, 0x54, 0x77, 0x30, 0x38, 0x38);


	public enum class WFPErrorCode {
		Success = ERROR_SUCCESS,
	    CalloutNotFound = FWP_E_CALLOUT_NOT_FOUND,
	    ConditionNotFound = FWP_E_CONDITION_NOT_FOUND,
	    FilterNotFound = FWP_E_FILTER_NOT_FOUND,
	    LayerNotFound = FWP_E_LAYER_NOT_FOUND,
	    ProviderNotFound = FWP_E_PROVIDER_NOT_FOUND,
	    ProviderContextNotFound = FWP_E_PROVIDER_CONTEXT_NOT_FOUND,
	    SublayerNotFound = FWP_E_SUBLAYER_NOT_FOUND,
	    NotFound = FWP_E_NOT_FOUND,
	    AlreadyExists = FWP_E_ALREADY_EXISTS,
	    InUse = FWP_E_IN_USE,
	    DynamicSessionInProgress = FWP_E_DYNAMIC_SESSION_IN_PROGRESS,
	    WrongSession = FWP_E_WRONG_SESSION,
	    NoTxnInProgress = FWP_E_NO_TXN_IN_PROGRESS,
	    TxnInProgress = FWP_E_TXN_IN_PROGRESS,
	    TxnAborted = FWP_E_TXN_ABORTED,
	    SessionAborted = FWP_E_SESSION_ABORTED,
	    IncompatibleTxn = FWP_E_INCOMPATIBLE_TXN,
	    Timeout = FWP_E_TIMEOUT,
	    NetEventsDisabled = FWP_E_NET_EVENTS_DISABLED,
	    IncompatibleLayer = FWP_E_INCOMPATIBLE_LAYER,
	    KmClientsOnly = FWP_E_KM_CLIENTS_ONLY,
	    LifetimeMismatch = FWP_E_LIFETIME_MISMATCH,
	    BuiltinObject = FWP_E_BUILTIN_OBJECT,
	    TooManyCallouts = FWP_E_TOO_MANY_CALLOUTS,
	    NotificationDropped = FWP_E_NOTIFICATION_DROPPED,
	    TrafficMismatch = FWP_E_TRAFFIC_MISMATCH,
	    IncompatibleSaState = FWP_E_INCOMPATIBLE_SA_STATE,
	    NullPointer = FWP_E_NULL_POINTER,
	    InvalidEnumerator = FWP_E_INVALID_ENUMERATOR,
	    InvalidFlags = FWP_E_INVALID_FLAGS,
	    InvalidNetMask = FWP_E_INVALID_NET_MASK,
	    InvalidRange = FWP_E_INVALID_RANGE,
	    InvalidInterval = FWP_E_INVALID_INTERVAL,
	    ZeroLengthArray = FWP_E_ZERO_LENGTH_ARRAY,
	    NullDisplayName = FWP_E_NULL_DISPLAY_NAME,
	    InvalidActionType = FWP_E_INVALID_ACTION_TYPE,
	    InvalidWeight = FWP_E_INVALID_WEIGHT,
	    MatchTypeMismatch = FWP_E_MATCH_TYPE_MISMATCH,
	    TypeMismatch = FWP_E_TYPE_MISMATCH,
	    OutOfBounds = FWP_E_OUT_OF_BOUNDS,
	    Reserved = FWP_E_RESERVED,
	    DuplicateCondition = FWP_E_DUPLICATE_CONDITION,
	    DuplicateKeymod = FWP_E_DUPLICATE_KEYMOD,
	    ActionIncompatibleWithLayer = FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER,
	    ActionIncompatibleWithSublayer = FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER,
	    ContextIncomaptibleWithLayer = FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER,
	    ContextIncompatibleWithCallout = FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT,
	    IncompatibleAuthMethod = FWP_E_INCOMPATIBLE_AUTH_METHOD,
	    IncompatibleDhGroup = FWP_E_INCOMPATIBLE_DH_GROUP,
	    EmNotSupported = FWP_E_EM_NOT_SUPPORTED,
	    NeverMatch = FWP_E_NEVER_MATCH,
	    ProviderContextMismatch = FWP_E_PROVIDER_CONTEXT_MISMATCH,
	    InvalidParameter = FWP_E_INVALID_PARAMETER,
	    TooManySublayers = FWP_E_TOO_MANY_SUBLAYERS,
	    CalloutNotificationFailed = FWP_E_CALLOUT_NOTIFICATION_FAILED,
	    InvalidAuthTransform = FWP_E_INVALID_AUTH_TRANSFORM,
	    InvalidCipherTransform = FWP_E_INVALID_CIPHER_TRANSFORM,
	};


	public ref class FirewallException : public System::Exception {
	private:
		int m_hresult;
	public:
		property int HResult {
			int get() { return m_hresult; };
			protected: void set(int value) { m_hresult = value; };
		}
		FirewallException() : System::Exception() { m_hresult = 0;  };
		FirewallException(int error) : System::Exception() { m_hresult = error; };
		FirewallException(String^ message) : System::Exception(message) { m_hresult = 0; };
		FirewallException(int error, String^ message) : System::Exception(message) { m_hresult = error; };
	};



	public ref class FirewallConditions sealed
	{
	private:
		std::vector<FWPM_FILTER_CONDITION> *conditions4;
		std::vector<FWPM_FILTER_CONDITION> *conditions6;
		bool hasIPv4;
		bool hasIPv6;
		bool needTransportLayer;
	public:
		// Object initializations / destruction
		FirewallConditions();
		~FirewallConditions();
		!FirewallConditions();

		// Add new filtering rule condition
		void Add(IPAddress^ addr);
		void Add(IPAddress^ addr, int prefix);
		void Add(IPAddress^ addrFirst, IPAddress^ addrLast);
		void Add(short port);
		void Add(short portLow, short portHigh);
		void Add(ProtocolType^ protocol);

		// Following methods should be private but friend with Firewall
		// class but unfortunately this is not possible with managed code

		// Get number of conditions
		bool HasIPv4() { return hasIPv4; };
		bool HasIPv6() { return hasIPv6; };

		// Get number of conditions
		size_t CountIPv4() { return conditions4->size(); };
		size_t CountIPv6() { return conditions6->size(); };

		// Get conditions
		FWPM_FILTER_CONDITION* GetIPv4() { return &(*conditions4)[0]; };
		FWPM_FILTER_CONDITION* GetIPv6() { return &(*conditions6)[0]; };

		// Get filtering layer required by conditions
		GUID LayerIPv4() { return needTransportLayer ? FWPM_LAYER_INBOUND_TRANSPORT_V4 : FWPM_LAYER_INBOUND_IPPACKET_V4; };
		GUID LayerIPv6() { return needTransportLayer ? FWPM_LAYER_INBOUND_TRANSPORT_V6 : FWPM_LAYER_INBOUND_IPPACKET_V6; };
	private:
		// Free memory allocated for filter condition options
		void FreeCondition(FWPM_FILTER_CONDITION &fwpFilterCondition);
	};



	public ref class Firewall sealed
	{
	private:
		// Singleton data
		static Object^ sync = gcnew Object();
		static Firewall^ m_instance;
		// Singleton constructor
		Firewall();
		Firewall(const Firewall%) { throw gcnew System::InvalidOperationException("Cannot copy-construct singleton"); }
		~Firewall();
		!Firewall();

		// WFP interface firewall data
		// Member with HANDLE data type create managed interior_ptr object
		// that would require pin_ptr<HANDLE> for each native WFP API call,
		// that's why we use unmanaged code in constructor to allocate
		// memory for WFP HANDLE* and that memory can be directly used
		// by native WFP functions
		HANDLE *p_hEngineHandle = NULL;
		FWPM_SESSION *m_Session = NULL;

	public:
		// Singleton instance
		static property Firewall^ Instance {
			Firewall^ get() {
				if (m_instance == nullptr)
				{
					Monitor::Enter(sync);
					try
					{
						if (m_instance == nullptr)
						{
							m_instance = gcnew Firewall();
						}
					}
					finally
					{
						Monitor::Exit(sync);
					}
				}
				return m_instance;
			}
		}

		// Firewall constants declaration
		static const Guid^ SESSION_KEY = gcnew Guid(F2BFW_SESSION_KEY.Data1, F2BFW_SESSION_KEY.Data2, F2BFW_SESSION_KEY.Data3,
			F2BFW_SESSION_KEY.Data4[0], F2BFW_SESSION_KEY.Data4[1], F2BFW_SESSION_KEY.Data4[2], F2BFW_SESSION_KEY.Data4[3],
			F2BFW_SESSION_KEY.Data4[4], F2BFW_SESSION_KEY.Data4[5], F2BFW_SESSION_KEY.Data4[6], F2BFW_SESSION_KEY.Data4[7]);
		static const Guid^ PROVIDER_KEY = gcnew Guid(F2BFW_PROVIDER_KEY.Data1, F2BFW_PROVIDER_KEY.Data2, F2BFW_PROVIDER_KEY.Data3,
			F2BFW_PROVIDER_KEY.Data4[0], F2BFW_PROVIDER_KEY.Data4[1], F2BFW_PROVIDER_KEY.Data4[2], F2BFW_PROVIDER_KEY.Data4[3],
			F2BFW_PROVIDER_KEY.Data4[4], F2BFW_PROVIDER_KEY.Data4[5], F2BFW_PROVIDER_KEY.Data4[6], F2BFW_PROVIDER_KEY.Data4[7]);
		static const Guid^ SUBLAYER_KEY = gcnew Guid(F2BFW_SUBLAYER_KEY.Data1, F2BFW_SUBLAYER_KEY.Data2, F2BFW_SUBLAYER_KEY.Data3,
			F2BFW_SUBLAYER_KEY.Data4[0], F2BFW_SUBLAYER_KEY.Data4[1], F2BFW_SUBLAYER_KEY.Data4[2], F2BFW_SUBLAYER_KEY.Data4[3],
			F2BFW_SUBLAYER_KEY.Data4[4], F2BFW_SUBLAYER_KEY.Data4[5], F2BFW_SUBLAYER_KEY.Data4[6], F2BFW_SUBLAYER_KEY.Data4[7]);

		// Create required WFP provider and sublayer for this module
		void Install();

		// Remove WFP provider and sublayer used by this module
		void Uninstall();

		// Add privileges to the user to "Add/Remove" filter rules
		void AddPrivileges(SecurityIdentifier^ sid);

		// Remove privileges from user to "Add/Remove" filter rules
		void RemovePrivileges(SecurityIdentifier^ sid);

#ifdef _DEBUG
		// Just dump WFP privileges on objects used by this module
		void DumpPrivileges();
#endif

		// Add new filtering rule
		UInt64 Add(String^ name, IPAddress^ addr) { return Add(name, addr, 0, false); };
		UInt64 Add(String^ name, IPAddress^ addr, UInt64 weight, bool permit) { return Add(name, addr, 128); };
		UInt64 Add(String^ name, IPAddress^ addr, int prefix) { return Add(name, addr, prefix, 0, false); };
		UInt64 Add(String^ name, IPAddress^ addr, int prefix, UInt64 weight, bool permit);
		UInt64 Add(String^ name, IPAddress^ addrFirst, IPAddress^ addrLast) { return Add(name, addrFirst, addrLast, 0, false); };
		UInt64 Add(String^ name, IPAddress^ addrFirst, IPAddress^ addrLast, UInt64 weight, bool permit);
		//UInt64 Add(String^ name, List<Object^>^ rules);
		//UInt64 Add(String^ name, char *data, UInt32 size);
		UInt64 AddIPv4(String^ name, FirewallConditions^ conditions) { return AddIPv4(name, conditions, 0, false); };
		UInt64 AddIPv4(String^ name, FirewallConditions^ conditions, UInt64 weight, bool permit);
		UInt64 AddIPv6(String^ name, FirewallConditions^ conditions) { return AddIPv6(name, conditions, 0, false); };
		UInt64 AddIPv6(String^ name, FirewallConditions^ conditions, UInt64 weight, bool permit);
		//UInt64 Add(String^ name, const GUID &layerKey, FWPM_FILTER_CONDITION &fwpFilterCondition, UInt32 iFilterCondition) { return Add(name, layerKey, fwpFilterCondition, iFilterCondition, 0, false); };
		UInt64 Add(String^ name, const GUID &layerKey, FWPM_FILTER_CONDITION &fwpFilterCondition, UInt32 iFilterCondition, UInt64 weight, bool permit);

		// Remove filter with defined Id
		void Remove(UInt64 id);

		// Remove all filter rules added by this module
		void Cleanup();

		// List all filter rules added by this module
		Dictionary<UInt64, String^>^ List();

	private:
		//void SetCondition(FWPM_FILTER_CONDITION &fwpFilterCondition, IPAddress^ addr);
		//void SetCondition(FWPM_FILTER_CONDITION &fwpFilterCondition, IPAddress^ addr, int prefix);
		//void SetCondition(FWPM_FILTER_CONDITION &fwpFilterCondition, IPAddress^ addrFirst, IPAddress^ addrLast);
		//void SetCondition(FWPM_FILTER_CONDITION &fwpFilterCondition, short port);
		//void SetCondition(FWPM_FILTER_CONDITION &fwpFilterCondition, short portLow, short portHigh);
		//void SetCondition(FWPM_FILTER_CONDITION &fwpFilterCondition, ProtocolType^ protocol);
		//void FreeCondition(FWPM_FILTER_CONDITION &fwpFilterCondition);
	};



	static String^ GetErrorText(DWORD rc);
	//static WCHAR * GetErrorText(DWORD rc);
	static WCHAR * FormatErrorText(WCHAR * msg, DWORD rc);
}
