// This is the main DLL file.
#include "stdafx.h"
#include "F2BWFP.h"
#include "Utils.h"

#pragma comment (lib, "fwpuclnt.lib")
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "Ws2_32.lib")

using namespace F2B;


// Singleton constructor
Firewall::Firewall()
{
	OutputDebugString(L"Firewall::Firewall");

	DWORD rc = ERROR_SUCCESS;

	// Initialize WFP structures
	p_hEngineHandle = new HANDLE;
	*p_hEngineHandle = NULL;
	m_Session = new FWPM_SESSION;
	::ZeroMemory(m_Session, sizeof(FWPM_SESSION));

	m_Session->displayData.name = L"F2B";
	m_Session->displayData.description = L"F2B Non Dynamic Session";
	//::CopyMemory(&m_Session->sessionKey, &F2BFW_SESSION_KEY, sizeof(GUID));
	m_Session->flags = 0; // non-dynamic session
	//m_Session->flags = FWPM_SESSION_FLAG_DYNAMIC;

	// Create packet filter engine
	//pin_ptr<HANDLE> p_hEngineHandle = &p_hEngineHandle; // prevent GC moving managed class pointer
	rc = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, m_Session, p_hEngineHandle);
	if (rc != ERROR_SUCCESS)
	{
		throw gcnew FirewallException(rc, "Firewall::Firewall(): FwpmEngineOpen failed (" + GetErrorText(rc) + ")");
	}

	OutputDebugString(L"Firewall::Firewall OK");
}


Firewall::~Firewall()
{
	// clean up code to release managed resource
	OutputDebugString(L"Firewall::~Firewall");

	// call finalizer to release unmanaged resources
	this->!Firewall();

	OutputDebugString(L"Firewall::~Firewall OK");
}


Firewall::!Firewall()
{
	// clean up code to release unmanaged resources
	OutputDebugString(L"Firewall::!Firewall");

	DWORD rc = ERROR_SUCCESS;

	if (p_hEngineHandle != NULL)
	{
		// Close packet filter engine
		rc = FwpmEngineClose(*p_hEngineHandle);
		if (rc != ERROR_SUCCESS)
		{
			OutputDebugString(FormatErrorText(L"Firewall::!Firewall: Unable to close packet filter engine", rc));
		}

		*p_hEngineHandle = NULL;
		delete p_hEngineHandle;
		p_hEngineHandle = NULL;
	}

	if (m_Session)
	{
		delete m_Session;
		m_Session = NULL;
	}

	OutputDebugString(L"Firewall::!Firewall OK");
}


// Create required WFP provider and sublayer for this module
void Firewall::Install()
{
	OutputDebugString(L"Firewall::Install");

	DWORD rc = ERROR_SUCCESS;
	FWPM_PROVIDER provider;
	FWPM_SUBLAYER subLayer;

	::ZeroMemory(&provider, sizeof(FWPM_PROVIDER));
	::ZeroMemory(&subLayer, sizeof(FWPM_SUBLAYER));

	// Use transaction to create provider & sublayer
	//rc = FwpmTransactionBegin(*p_hEngineHandle, 0);

	// Create WFP provider
	provider.providerKey = F2BFW_PROVIDER_KEY;
	provider.displayData.name = L"F2B";
	provider.displayData.description = L"F2B Provider";
	provider.serviceName = L"F2BFW"; // BFE loads persistent rules for auto-start services
	provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

	rc = FwpmProviderAdd(*p_hEngineHandle, &provider, NULL);

	// Ignore FWP_E_ALREADY_EXISTS. This allows install to be re-run as needed
	// to repair a broken configuration.
	if (rc == ERROR_SUCCESS)
	{
		OutputDebugString(L"Firewall::Install: Created new provider");
	}
	else if (rc == FWP_E_ALREADY_EXISTS)
	{
		OutputDebugString(L"Firewall::Install: Provider already exists");
	}
	else
	{
		throw gcnew FirewallException(rc, "Firewall::Install: FwpmProviderAdd failed (" + GetErrorText(rc) + ")");
	}

	// Create WFP sublayer
	subLayer.subLayerKey = F2BFW_SUBLAYER_KEY;
	subLayer.providerKey = (GUID*)&F2BFW_PROVIDER_KEY;
	subLayer.displayData.name = L"F2B";
	subLayer.displayData.description = L"F2B SubLayer";
	subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
	subLayer.weight = 0x1000; // important
	subLayer.weight = 0x0000; // weight < 2 => processed after default Windows Firewall (GUI)

	rc = FwpmSubLayerAdd(*p_hEngineHandle, &subLayer, NULL);

	// Ignore FWP_E_ALREADY_EXISTS. This allows install to be re-run as needed
	// to repair a broken configuration.
	if (rc == ERROR_SUCCESS)
	{
		OutputDebugString(L"Firewall::Install: Created new subLayer");
	}
	else if (rc == FWP_E_ALREADY_EXISTS)
	{
		OutputDebugString(L"Firewall::Install: SubLayer already exists");
	}
	else
	{
		throw gcnew FirewallException(rc, "Firewall::Install: FwpmSubLayerAdd failed (" + GetErrorText(rc) + ")");
	}
}


// Remove WFP provider and sublayer used by this module
void Firewall::Uninstall()
{
	OutputDebugString(L"Firewall::Uninstall");

	DWORD rc = ERROR_SUCCESS;

	Cleanup();

	// Use transaction to create provider & sublayer
	//rc = FwpmTransactionBegin(*p_hEngineHandle, 0);

	// Remove WFP sublayer
	rc = FwpmSubLayerDeleteByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY);
	if (rc == ERROR_SUCCESS)
	{
		OutputDebugString(L"Firewall::Uninstall: Removed subLayer");
	}
	else if (rc == FWP_E_SUBLAYER_NOT_FOUND)
	{
		OutputDebugString(L"Firewall::Uninstall: SubLayer doesn't exist");
	}
	else
	{
		throw gcnew FirewallException(rc, "Firewall::Uninstall: FwpmSubLayerDeleteByKey failed (" + GetErrorText(rc) + ")");
	}

	// Remove WFP provider
	rc = FwpmProviderDeleteByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY);
	if (rc == ERROR_SUCCESS)
	{
		OutputDebugString(L"Firewall::Uninstall: Removed provider");
	}
	else if (rc == FWP_E_PROVIDER_NOT_FOUND)
	{
		OutputDebugString(L"Firewall::Uninstall: Provider doesn't exist");
	}
	else
	{
		throw gcnew FirewallException(rc, "Firewall::Uninstall: FwpmProviderDeleteByKey failed (" + GetErrorText(rc) + ")");
	}

	// Use transaction to create provider & sublayer
	// rc = FwpmTransactionCommit0(engine);
}


// Add privileges to the user to "Add/Remove" filter rules
void Firewall::AddPrivileges(SecurityIdentifier^ sid)
{
	// Check DACL and add access to provider/sublayer for given user
	if (sid == nullptr)
	{
		OutputDebugString(L"Firewall::AddPrivileges: Undefined SID NULL");
		return;
	}

	OutputDebugString(L"Firewall::AddPrivileges: Add DACL privileges for user with given SID");
	DWORD rc = ERROR_SUCCESS;
	PACL pDacl;
	PSECURITY_DESCRIPTOR securityDescriptor;

	array<unsigned char>^ aSid = gcnew array<unsigned char>(sid->BinaryLength);
	sid->GetBinaryForm(aSid, 0);
	pin_ptr<unsigned char> pSid = &aSid[0]; // GC
    //PSID pSid = &aSid;

	// Set provider DACL for given user
	OutputDebugString(L"Firewall::AddPrivileges: FwpmProviderGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmProviderGetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		BOOL bExists = false;

		// Loop through the ACEs and search for user SID.
		for (WORD cAce = 0; !bExists && cAce < pDacl->AceCount; cAce++)
		{
			ACCESS_ALLOWED_ACE * pAce = NULL;

			// Get ACE info
			if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: GetAce failed: ", GetLastError()));
				continue;
			}

			if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
			{
				continue;
			}

			bExists = EqualSid(&pAce->SidStart, pSid);
		}

		if (bExists)
		{
			OutputDebugString(L"Firewall::AddPrivileges: ACL for user to WFP provider already exists");
		}
		else
		{
			OutputDebugString(L"Firewall::AddPrivileges: Add ACL for user to WFP provider");

			PACL pNewDacl = NULL;
			EXPLICIT_ACCESS ea;

			// Initialize an EXPLICIT_ACCESS structure for the new ACE. 
			ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
			ea.grfAccessPermissions = FWPM_ACTRL_READ | FWPM_ACTRL_ADD_LINK;
			ea.grfAccessMode = GRANT_ACCESS;
			ea.grfInheritance = NO_INHERITANCE;
			ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea.Trustee.ptstrName = (LPTSTR)pSid;
			//ea.Trustee.ptstrName = user;

			// Create a new ACL that merges the new ACE
			// into the existing DACL.
			rc = SetEntriesInAcl(1, &ea, pDacl, &pNewDacl);
			if (rc == ERROR_SUCCESS)
			{
				rc = FwpmProviderSetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
				if (rc == ERROR_SUCCESS)
				{
					OutputDebugString(L"Firewall::AddPrivileges: FwpmProviderSetSecurityInfoByKey OK");
				}
				else
				{
					OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmProviderSetSecurityInfoByKey failed", rc));
				}
			}
			else
			{
				OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: SetEntriesInAcl failed", rc));
			}

			if (pNewDacl != NULL)
			{
				LocalFree(pNewDacl);
			}
		}
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmProviderGetSecurityInfoByKey failed, can't modify provider privileges", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Set layer DACL for given user
	GUID *layers[] = {
		(GUID *)&FWPM_LAYER_INBOUND_IPPACKET_V4, (GUID *)&FWPM_LAYER_INBOUND_IPPACKET_V6,
		(GUID *)&FWPM_LAYER_INBOUND_TRANSPORT_V4, (GUID *)&FWPM_LAYER_INBOUND_TRANSPORT_V6,
		//(GUID *)&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, (GUID *)&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		NULL
	};
	for (int cLayer = 0; layers[cLayer] != NULL; cLayer++)
	{
		OutputDebugString(L"Firewall::AddPrivileges: FwpmLayerGetSecurityInfoByKey");
		pDacl = NULL;
		securityDescriptor = NULL;
		rc = FwpmLayerGetSecurityInfoByKey(*p_hEngineHandle, layers[cLayer], DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

		if (rc == ERROR_SUCCESS)
		{
			BOOL bExists = false;

			// Loop through the ACEs and search for user SID.
			for (WORD cAce = 0; !bExists && cAce < pDacl->AceCount; cAce++)
			{
				ACCESS_ALLOWED_ACE * pAce = NULL;

				// Get ACE info
				if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
				{
					OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: GetAce failed: ", GetLastError()));
					continue;
				}

				if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
				{
					continue;
				}

				bExists = EqualSid(&pAce->SidStart, pSid);
			}

			if (bExists)
			{
				OutputDebugString(L"Firewall::AddPrivileges: ACL for user to WFP layer already exists");
			}
			else
			{
				OutputDebugString(L"Firewall::AddPrivileges: Add ACL for user to WFP layer");

				PACL pNewDacl = NULL;
				EXPLICIT_ACCESS ea;

				// Initialize an EXPLICIT_ACCESS structure for the new ACE. 
				ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
				ea.grfAccessPermissions = FWPM_ACTRL_ADD_LINK;
				ea.grfAccessMode = GRANT_ACCESS;
				ea.grfInheritance = NO_INHERITANCE;
				ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
				ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
				ea.Trustee.ptstrName = (LPTSTR)pSid;
				//ea.Trustee.ptstrName = user;

				// Create a new ACL that merges the new ACE
				// into the existing DACL.
				rc = SetEntriesInAcl(1, &ea, pDacl, &pNewDacl);
				if (rc == ERROR_SUCCESS)
				{
					rc = FwpmLayerSetSecurityInfoByKey(*p_hEngineHandle, layers[cLayer], DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
					if (rc == ERROR_SUCCESS)
					{
						OutputDebugString(L"Firewall::AddPrivileges: FwpmLayerSetSecurityInfoByKey OK");
					}
					else
					{
						OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmlayerSetSecurityInfoByKey failed", rc));
					}
				}
				else
				{
					OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: SetEntriesInAcl failed", rc));
				}

				if (pNewDacl != NULL)
				{
					LocalFree(pNewDacl);
				}
			}
		}
		else
		{
			OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmLayerGetSecurityInfoByKey failed", rc));
		}

		if (securityDescriptor != NULL)
		{
			FwpmFreeMemory((void **)&securityDescriptor);
		}
	}

	// Set subLayer DACL for given user
	OutputDebugString(L"Firewall::AddPrivileges: FwpmSubLayerGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmSubLayerGetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		BOOL bExists = false;

		// Loop through the ACEs and search for user SID.
		for (WORD cAce = 0; !bExists && cAce < pDacl->AceCount; cAce++)
		{
			ACCESS_ALLOWED_ACE * pAce = NULL;

			// Get ACE info
			if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: GetAce failed: ", GetLastError()));
				continue;
			}

			if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
			{
				continue;
			}

			bExists = EqualSid(&pAce->SidStart, pSid);
		}

		if (bExists)
		{
			OutputDebugString(L"Firewall::AddPrivileges: ACL for user to WFP subLayer already exists");
		}
		else
		{
			OutputDebugString(L"Firewall::AddPrivileges: Add ACL for user to WFP subLayer");

			PACL pNewDacl = NULL;
			EXPLICIT_ACCESS ea;

			// Initialize an EXPLICIT_ACCESS structure for the new ACE. 
			ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
			ea.grfAccessPermissions = FWPM_ACTRL_READ | FWPM_ACTRL_ADD_LINK;
			ea.grfAccessMode = GRANT_ACCESS;
			ea.grfInheritance = NO_INHERITANCE;
			ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea.Trustee.ptstrName = (LPTSTR)pSid;
			//ea.Trustee.ptstrName = user;

			// Create a new ACL that merges the new ACE
			// into the existing DACL.
			rc = SetEntriesInAcl(1, &ea, pDacl, &pNewDacl);
			if (rc == ERROR_SUCCESS)
			{
				rc = FwpmSubLayerSetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
				if (rc == ERROR_SUCCESS)
				{
					OutputDebugString(L"Firewall::AddPrivileges: FwpmSubLayerSetSecurityInfoByKey OK");
				}
				else
				{
					OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmSubLayerSetSecurityInfoByKey failed", rc));
				}
			}
			else
			{
				OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: SetEntriesInAcl failed", rc));
			}

			if (pNewDacl != NULL)
			{
				LocalFree(pNewDacl);
			}
		}
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmSubLayerGetSecurityInfoByKey failed", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Set filter DACL for given user
	OutputDebugString(L"Firewall::AddPrivileges: FwpmFilterGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmFilterGetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		BOOL bExists = false;

		// Loop through the ACEs and search for user SID.
		for (WORD cAce = 0; !bExists && cAce < pDacl->AceCount; cAce++)
		{
			ACCESS_ALLOWED_ACE * pAce = NULL;

			// Get ACE info
			if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: GetAce failed: ", GetLastError()));
				continue;
			}

			if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
			{
				continue;
			}

			bExists = EqualSid(&pAce->SidStart, pSid);
		}

		if (bExists)
		{
			OutputDebugString(L"Firewall::AddPrivileges: ACL for user to WFP filter already exists");
		}
		else
		{
			OutputDebugString(L"Firewall::AddPrivileges: Add ACL for user to WFP filter");

			// this doesn't work unless you allocate new pNewDacl first with sufficient
			// size and copy all ACE + call AddAccessAllowedAce ... using EA is easier
			//if (AddAccessAllowedAce(pDacl, ACL_, FWPM_ACTRL_READ, pSid) == ERROR_SUCCESS)
			//{
			//	rc = FwpmFilterSetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);
			//	if (rc == ERROR_SUCCESS)
			//	{
			//		OutputDebugString(L"Firewall::AddPrivileges: FwpmFilterSetSecurityInfoByKey OK");
			//	}
			//	else
			//	{
			//		OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmFilterSetSecurityInfoByKey failed: ", rc));
			//		throw new std::exception("FwpmFilterSetSecurityInfoByKey failed");
			//	}
			//}
			//else
			//{
			//	OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: SetEntriesInAcl failed: ", rc));
			//	throw new std::exception("SetEntriesInAcl failed");
			//}

			PACL pNewDacl = NULL;
			EXPLICIT_ACCESS ea[2];

			// Initialize an EXPLICIT_ACCESS structure for the new ACE. 
			ZeroMemory(&ea, 2*sizeof(EXPLICIT_ACCESS));
			ea[0].grfAccessPermissions = FWPM_ACTRL_ENUM | FWPM_ACTRL_ADD;
			ea[0].grfAccessMode = GRANT_ACCESS;
			ea[0].grfInheritance = NO_INHERITANCE;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea[0].Trustee.ptstrName = (LPTSTR)pSid;
			//ea[0].Trustee.ptstrName = user;
			ea[1].grfAccessPermissions = FWPM_ACTRL_READ | DELETE;
			ea[1].grfAccessMode = GRANT_ACCESS;
			ea[1].grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea[1].Trustee.ptstrName = (LPTSTR)pSid;
			//ea[1].Trustee.ptstrName = user;

			// Create a new ACL that merges the new ACE
			// into the existing DACL.
			rc = SetEntriesInAcl(2, ea, pDacl, &pNewDacl);
			if (rc == ERROR_SUCCESS)
			{
				rc = FwpmFilterSetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
				if (rc == ERROR_SUCCESS)
				{
					OutputDebugString(L"Firewall::AddPrivileges: FwpmFilterSetSecurityInfoByKey OK");
				}
				else
				{
					OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmFilterSetSecurityInfoByKey failed", rc));
				}
			}
			else
			{
				OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: SetEntriesInAcl failed", rc));
			}

			if (pNewDacl != NULL)
			{
				LocalFree(pNewDacl);
			}
		}
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::AddPrivileges: FwpmFilterGetSecurityInfoByKey failed", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}
}


// Remove privileges from user to "Add/Remove" filter rules
void Firewall::RemovePrivileges(SecurityIdentifier^ sid)
{
	// Check DACL and add access to provider/sublayer for given user
	if (sid == nullptr)
	{
		OutputDebugString(L"Firewall::RemovePrivileges: Undefined SID NULL");
		return;
	}

	OutputDebugString(L"Firewall::RemovePrivileges: Remove DACL privileges for user with given SID");
	DWORD rc = ERROR_SUCCESS;
	PACL pDacl;
	PSECURITY_DESCRIPTOR securityDescriptor;

	array<unsigned char>^ aSid = gcnew array<unsigned char>(sid->BinaryLength);
	sid->GetBinaryForm(aSid, 0);
	pin_ptr<unsigned char> pSid = &aSid[0]; // GC
	//PSID pSid = &aSid;

	// Set provider DACL for given user
	OutputDebugString(L"Firewall::RemovePrivileges: FwpmProviderGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmProviderGetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		BOOL bDeleted = false;

		// Loop through the ACEs and search for user SID.
		for (int cAce = pDacl->AceCount - 1; cAce >= 0; cAce--)
		{
			ACCESS_ALLOWED_ACE * pAce = NULL;

			// Get ACE info
			if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: GetAce failed: ", GetLastError()));
				continue;
			}

			if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
			{
				continue;
			}

			if (!EqualSid(&pAce->SidStart, pSid))
			{
				continue;
			}

			// Delete the ACE from the DACL.
			if (DeleteAce(pDacl, cAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: Unable to remove ACL for user to WFP provider", rc));
			}
			else
			{
				OutputDebugString(L"Firewall::RemovePrivileges: Removed ACL for user to WFP provider");
				bDeleted = true;
			}
		}

		if (bDeleted)
		{
			rc = FwpmProviderSetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);
			if (rc == ERROR_SUCCESS)
			{
				OutputDebugString(L"Firewall::RemovePrivileges: FwpmProviderSetSecurityInfoByKey OK");
			}
			else
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmProviderSetSecurityInfoByKey failed", rc));
			}
		}
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmProviderGetSecurityInfoByKey failed", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Reset layer DACL for given user
	GUID *layers[] = {
		(GUID *)&FWPM_LAYER_INBOUND_IPPACKET_V4, (GUID *)&FWPM_LAYER_INBOUND_IPPACKET_V6,
		(GUID *)&FWPM_LAYER_INBOUND_TRANSPORT_V4, (GUID *)&FWPM_LAYER_INBOUND_TRANSPORT_V6,
		//(GUID *)&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, (GUID *)&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		NULL
	};
	for (int cLayer = 0; layers[cLayer] != NULL; cLayer++)
	{
		OutputDebugString(L"Firewall::RemovePrivileges: FwpmLayerGetSecurityInfoByKey");
		pDacl = NULL;
		securityDescriptor = NULL;
		rc = FwpmLayerGetSecurityInfoByKey(*p_hEngineHandle, layers[cLayer], DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

		if (rc == ERROR_SUCCESS)
		{
			BOOL bDeleted = false;

			// Loop through the ACEs and search for user SID.
			for (int cAce = pDacl->AceCount - 1; cAce >= 0; cAce--)
			{
				ACCESS_ALLOWED_ACE * pAce = NULL;

				// Get ACE info
				if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
				{
					OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: GetAce failed: ", GetLastError()));
					continue;
				}

				if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
				{
					continue;
				}

				if (!EqualSid(&pAce->SidStart, pSid))
				{
					continue;
				}

				// Delete the ACE from the DACL.
				if (DeleteAce(pDacl, cAce) == FALSE)
				{
					OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: Unable to remove ACL for user to WFP layer", rc));
				}
				else
				{
					OutputDebugString(L"Firewall::RemovePrivileges: Removed ACL for user to WFP layer");
					bDeleted = true;
				}
			}

			if (bDeleted)
			{
				rc = FwpmLayerSetSecurityInfoByKey(*p_hEngineHandle, layers[cLayer], DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);
				if (rc == ERROR_SUCCESS)
				{
					OutputDebugString(L"Firewall::RemovePrivileges: FwpmLayerSetSecurityInfoByKey OK");
				}
				else
				{
					OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmLayerSetSecurityInfoByKey failed", rc));
				}
			}
		}
		else
		{
			OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmLayerGetSecurityInfoByKey failed", rc));
		}

		if (securityDescriptor != NULL)
		{
			FwpmFreeMemory((void **)&securityDescriptor);
		}
	}

	// Set subLayer DACL for given user
	OutputDebugString(L"Firewall::RemovePrivileges: FwpmSubLayerGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmSubLayerGetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		BOOL bDeleted = false;

		// Loop through the ACEs and search for user SID.
		for (int cAce = pDacl->AceCount - 1; cAce >= 0; cAce--)
		{
			ACCESS_ALLOWED_ACE * pAce = NULL;

			// Get ACE info
			if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: GetAce failed: ", GetLastError()));
				continue;
			}

			if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
			{
				continue;
			}

			if (!EqualSid(&pAce->SidStart, pSid))
			{
				continue;
			}

			// Delete the ACE from the DACL.
			if (DeleteAce(pDacl, cAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: Unable to remove ACL for user to WFP subLayer", rc));
			}
			else
			{
				OutputDebugString(L"Firewall::RemovePrivileges: Removed ACL for user to WFP subLayer");
				bDeleted = true;
			}
		}

		if (bDeleted)
		{
			rc = FwpmSubLayerSetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);
			if (rc == ERROR_SUCCESS)
			{
				OutputDebugString(L"Firewall::RemovePrivileges: FwpmSubLayerSetSecurityInfoByKey OK");
			}
			else
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmSubLayerSetSecurityInfoByKey failed", rc));
			}
		}
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmSubLayerGetSecurityInfoByKey failed", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Set filter DACL for given user
	OutputDebugString(L"Firewall::RemovePrivileges: FwpmFilterGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmFilterGetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		BOOL bDeleted = false;

		// Loop through the ACEs and search for user SID.
		for (int cAce = pDacl->AceCount - 1; cAce >= 0; cAce--)
		{
			ACCESS_ALLOWED_ACE * pAce = NULL;

			// Get ACE info
			if (GetAce(pDacl, cAce, (LPVOID*)&pAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: GetAce failed: ", GetLastError()));
				continue;
			}

			if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
			{
				continue;
			}

			if (!EqualSid(&pAce->SidStart, pSid))
			{
				continue;
			}

			// Delete the ACE from the DACL.
			if (DeleteAce(pDacl, cAce) == FALSE)
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: Unable to remove ACL for user to WFP filter", rc));
			}
			else
			{
				OutputDebugString(L"Firewall::RemovePrivileges: Removed ACL for user to WFP filter");
				bDeleted = true;
			}
		}

		if (bDeleted)
		{
			rc = FwpmFilterSetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);
			if (rc == ERROR_SUCCESS)
			{
				OutputDebugString(L"Firewall::RemovePrivileges: FwpmFilterSetSecurityInfoByKey OK");
			}
			else
			{
				OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmFilterSetSecurityInfoByKey failed", rc));
			}
		}
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmFilterGetSecurityInfoByKey failed", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}
}


#ifdef _DEBUG
// Just dump F2B WFP structures
void Firewall::DumpWFP()
{
	OutputDebugString(L"Firewall::DumpWFP");
	DWORD rc = ERROR_SUCCESS;
	FWPM_PROVIDER* pProvider = 0;
	FWPM_SUBLAYER* pSubLayer = 0;

	rc = FwpmProviderGetByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY, &pProvider);
	if (rc == ERROR_SUCCESS)
	{
		wprintf(L"F2B Provider %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
			F2BFW_PROVIDER_KEY.Data1, F2BFW_PROVIDER_KEY.Data2, F2BFW_PROVIDER_KEY.Data3,
			F2BFW_PROVIDER_KEY.Data4[0], F2BFW_PROVIDER_KEY.Data4[1], F2BFW_PROVIDER_KEY.Data4[2], F2BFW_PROVIDER_KEY.Data4[3],
			F2BFW_PROVIDER_KEY.Data4[4], F2BFW_PROVIDER_KEY.Data4[5], F2BFW_PROVIDER_KEY.Data4[6], F2BFW_PROVIDER_KEY.Data4[7]);

		FWPM_DISPLAY_DATA0 *d = &pProvider->displayData;
		wprintf(L"  name: %s\n", d->name);
		if (d->description) wprintf(L"  description: %s\n", d->description);
		if (pProvider->serviceName) wprintf(L"  service name: %s\n", pProvider->serviceName);
		wprintf(L"  flags: %04hx\n", pProvider->flags);

		FwpmFreeMemory((VOID**)&pProvider);
	}
	else if (rc == FWP_E_PROVIDER_NOT_FOUND)
	{
		wprintf(L"F2B Provider %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX not found\n",
			F2BFW_PROVIDER_KEY.Data1, F2BFW_PROVIDER_KEY.Data2, F2BFW_PROVIDER_KEY.Data3,
			F2BFW_PROVIDER_KEY.Data4[0], F2BFW_PROVIDER_KEY.Data4[1], F2BFW_PROVIDER_KEY.Data4[2], F2BFW_PROVIDER_KEY.Data4[3],
			F2BFW_PROVIDER_KEY.Data4[4], F2BFW_PROVIDER_KEY.Data4[5], F2BFW_PROVIDER_KEY.Data4[6], F2BFW_PROVIDER_KEY.Data4[7]);
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::DumpWFP: FwpmProviderGetByKey failed", rc));
	}

	rc = FwpmSubLayerGetByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY, &pSubLayer);
	if (rc == ERROR_SUCCESS)
	{
		wprintf(L"F2B SubLayer %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
			F2BFW_SUBLAYER_KEY.Data1, F2BFW_SUBLAYER_KEY.Data2, F2BFW_SUBLAYER_KEY.Data3,
			F2BFW_SUBLAYER_KEY.Data4[0], F2BFW_SUBLAYER_KEY.Data4[1], F2BFW_SUBLAYER_KEY.Data4[2], F2BFW_SUBLAYER_KEY.Data4[3],
			F2BFW_SUBLAYER_KEY.Data4[4], F2BFW_SUBLAYER_KEY.Data4[5], F2BFW_SUBLAYER_KEY.Data4[6], F2BFW_SUBLAYER_KEY.Data4[7]);

		FWPM_DISPLAY_DATA0 *d = &pSubLayer->displayData;
		wprintf(L"  name: %s\n", d->name);
		if (d->description) wprintf(L"  description: %s\n", d->description);
		wprintf(L"  flags: %04hx\n", pSubLayer->flags);
		wprintf(L"  weight: %i\n", pSubLayer->weight);
		if (pSubLayer->providerKey)
			wprintf(L"  provider: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
				pSubLayer->providerKey->Data1, pSubLayer->providerKey->Data2, pSubLayer->providerKey->Data3,
				pSubLayer->providerKey->Data4[0], pSubLayer->providerKey->Data4[1], pSubLayer->providerKey->Data4[2], pSubLayer->providerKey->Data4[3],
				pSubLayer->providerKey->Data4[4], pSubLayer->providerKey->Data4[5], pSubLayer->providerKey->Data4[6], pSubLayer->providerKey->Data4[7]);

		FwpmFreeMemory((VOID**)&pSubLayer);
	}
	else if (rc == FWP_E_SUBLAYER_NOT_FOUND)
	{
		wprintf(L"F2B SubLayer %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX not found\n",
			F2BFW_SUBLAYER_KEY.Data1, F2BFW_SUBLAYER_KEY.Data2, F2BFW_SUBLAYER_KEY.Data3,
			F2BFW_SUBLAYER_KEY.Data4[0], F2BFW_SUBLAYER_KEY.Data4[1], F2BFW_SUBLAYER_KEY.Data4[2], F2BFW_SUBLAYER_KEY.Data4[3],
			F2BFW_SUBLAYER_KEY.Data4[4], F2BFW_SUBLAYER_KEY.Data4[5], F2BFW_SUBLAYER_KEY.Data4[6], F2BFW_SUBLAYER_KEY.Data4[7]);
	}
	else
	{
		OutputDebugString(FormatErrorText(L"Firewall::DumpWFP: FwpmProviderGetByKey failed", rc));
	}
}

// Just dump WFP privileges on objects used by this module
void Firewall::DumpPrivileges()
{
	OutputDebugString(L"Firewall::DumpPrivileges");
	DWORD rc = ERROR_SUCCESS;
	PACL pDacl;
	PSECURITY_DESCRIPTOR securityDescriptor;

	OutputDebugString(L"Firewall::DumpPrivileges: FwpmProviderGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmProviderGetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_PROVIDER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		PWSTR stringSD;
		ULONG stringSDLen = 0;

		ConvertSecurityDescriptorToStringSecurityDescriptor(
			securityDescriptor,
			SDDL_REVISION_1,
			OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION |
			ATTRIBUTE_SECURITY_INFORMATION |
			SCOPE_SECURITY_INFORMATION,
			&stringSD,
			&stringSDLen
			);

		wprintf(L"Provider SD: %s\n", stringSD);
		LocalFree(stringSD);
	}
	else
	{
		wprintf(L"Provider SD: %s\n", FormatErrorText(L"", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Reset layer DACL for given user
	GUID *layers[] = {
		(GUID *)&FWPM_LAYER_INBOUND_IPPACKET_V4, (GUID *)&FWPM_LAYER_INBOUND_IPPACKET_V6,
		(GUID *)&FWPM_LAYER_INBOUND_TRANSPORT_V4, (GUID *)&FWPM_LAYER_INBOUND_TRANSPORT_V6,
		//(GUID *)&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, (GUID *)&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		NULL
	};
	for (int cLayer = 0; layers[cLayer] != NULL; cLayer++)
	{
		OutputDebugString(L"Firewall::DumpPrivileges: FwpmLayerGetSecurityInfoByKey");
		pDacl = NULL;
		securityDescriptor = NULL;
		rc = FwpmLayerGetSecurityInfoByKey(*p_hEngineHandle, layers[cLayer], DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

		if (rc == ERROR_SUCCESS)
		{
			PWSTR stringSD;
			ULONG stringSDLen = 0;

			ConvertSecurityDescriptorToStringSecurityDescriptor(
				securityDescriptor,
				SDDL_REVISION_1,
				OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION |
				LABEL_SECURITY_INFORMATION |
				ATTRIBUTE_SECURITY_INFORMATION |
				SCOPE_SECURITY_INFORMATION,
				&stringSD,
				&stringSDLen
				);

			wprintf(L"Layer SD: %s\n", stringSD);
			LocalFree(stringSD);
		}
		else
		{
			wprintf(L"Layer SD: %s\n", FormatErrorText(L"", rc));
		}

		if (securityDescriptor != NULL)
		{
			FwpmFreeMemory((void **)&securityDescriptor);
		}
	}

	// Set subLayer DACL for given user
	OutputDebugString(L"Firewall::DumpPrivileges: FwpmSubLayerGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmSubLayerGetSecurityInfoByKey(*p_hEngineHandle, &F2BFW_SUBLAYER_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		PWSTR stringSD;
		ULONG stringSDLen = 0;

		ConvertSecurityDescriptorToStringSecurityDescriptor(
			securityDescriptor,
			SDDL_REVISION_1,
			OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION |
			ATTRIBUTE_SECURITY_INFORMATION |
			SCOPE_SECURITY_INFORMATION,
			&stringSD,
			&stringSDLen
			);

		wprintf(L"SubLayer SD: %s\n", stringSD);
		LocalFree(stringSD);
	}
	else
	{
		wprintf(L"SubLayer SD: %s\n", FormatErrorText(L"", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Set filter DACL for given user
	OutputDebugString(L"Firewall::DumpPrivileges: FwpmFilterGetSecurityInfoByKey");
	pDacl = NULL;
	securityDescriptor = NULL;
	rc = FwpmFilterGetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

	if (rc == ERROR_SUCCESS)
	{
		PWSTR stringSD;
		ULONG stringSDLen = 0;

		ConvertSecurityDescriptorToStringSecurityDescriptor(
			securityDescriptor,
			SDDL_REVISION_1,
			OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION |
			ATTRIBUTE_SECURITY_INFORMATION |
			SCOPE_SECURITY_INFORMATION,
			&stringSD,
			&stringSDLen
			);

		wprintf(L"Filter SD: %s\n", stringSD);
		LocalFree(stringSD);
	}
	else
	{
		wprintf(L"Filter SD: %s\n", FormatErrorText(L"", rc));
	}

	if (securityDescriptor != NULL)
	{
		FwpmFreeMemory((void **)&securityDescriptor);
	}

	// Remove READ/DELETE privileges to individual filter rules
	HANDLE m_hFilterEnumHandle = NULL;
	FWPM_FILTER** pFilter = NULL;
	UINT32 nFilter;

	// filter
	rc = FwpmFilterCreateEnumHandle(*p_hEngineHandle, NULL, &m_hFilterEnumHandle);
	if (rc != ERROR_SUCCESS) {
		throw gcnew FirewallException(rc, "Firewall::DumpPrivileges: FwpmFilterCreateEnumHandle failed (" + GetErrorText(rc) + ")");
	}

	rc = FwpmFilterEnum(*p_hEngineHandle, m_hFilterEnumHandle, INFINITE, &pFilter, &nFilter);
	if (rc != ERROR_SUCCESS) {
		FwpmFilterDestroyEnumHandle(*p_hEngineHandle, m_hFilterEnumHandle);
		throw gcnew FirewallException(rc, "Firewall::DumpPrivileges: FwpmFilterEnum failed (" + GetErrorText(rc) + ")");
	}

	for (UINT32 i = 0; i < nFilter; i++)
	{
		FWPM_FILTER *f = pFilter[i];
		if (f->providerKey == NULL)
			continue;
		if (!IsEqualGUID(*f->providerKey, F2BFW_PROVIDER_KEY))
			continue;
		if (!IsEqualGUID(f->subLayerKey, F2BFW_SUBLAYER_KEY))
			continue;

		// Set filter DACL for given user
		OutputDebugString(L"Firewall::RemovePrivileges: FwpmFilterGetSecurityInfoByKey");
		pDacl = NULL;
		securityDescriptor = NULL;
		rc = FwpmFilterGetSecurityInfoByKey(*p_hEngineHandle, &f->filterKey, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);

		if (rc == ERROR_SUCCESS)
		{
			PWSTR stringSD;
			ULONG stringSDLen = 0;

			ConvertSecurityDescriptorToStringSecurityDescriptor(
				securityDescriptor,
				SDDL_REVISION_1,
				OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION |
				LABEL_SECURITY_INFORMATION |
				ATTRIBUTE_SECURITY_INFORMATION |
				SCOPE_SECURITY_INFORMATION,
				&stringSD,
				&stringSDLen
				);

			wprintf(L"Filter(%llu) SD: %s\n", f->filterId, stringSD);
			LocalFree(stringSD);
		}
		else
		{
			wprintf(L"Filter(%llu) SD: %s\n", f->filterId, FormatErrorText(L"", rc));
		}

		if (securityDescriptor != NULL)
		{
			FwpmFreeMemory((void **)&securityDescriptor);
		}
	}

	if (pFilter != NULL)
	{
		FwpmFreeMemory((void**)&pFilter);
	}

	rc = FwpmFilterDestroyEnumHandle(*p_hEngineHandle, m_hFilterEnumHandle);
	if (rc != ERROR_SUCCESS) {
		OutputDebugString(FormatErrorText(L"Firewall::RemovePrivileges: FwpmFilterDestroyEnumHandle failed: ", rc));
	}
}
#endif


// Add new filtering rule
UInt64 Firewall::Add(String^ name, IPAddress^ addr, int prefix, UInt64 weight, bool permit, bool persistent)
{
	OutputDebugString(L"Firewall::Add(name, addr, prefix)");

	FWPM_FILTER_CONDITION fwpFilterCondition;

	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));

	if (addr->IsIPv4MappedToIPv6)
	{
		addr = addr->MapToIPv4();
		if (prefix >= 96)
		{
			prefix -= 96;
		}
	}

	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	fwpFilterCondition.matchType = FWP_MATCH_EQUAL;
	if (addr->AddressFamily == Sockets::AddressFamily::InterNetwork)
	{
		// IPv4 address
		FWP_V4_ADDR_AND_MASK fwpAddr4AndMask;
		::ZeroMemory(&fwpAddr4AndMask, sizeof(FWP_V4_ADDR_AND_MASK));

		fwpFilterCondition.conditionValue.type = FWP_V4_ADDR_MASK;
		fwpFilterCondition.conditionValue.v4AddrMask = &fwpAddr4AndMask;
		array<unsigned char>^ addrBytes = addr->GetAddressBytes();
		pin_ptr<unsigned char> pAddrBytes = &addrBytes[0];
		fwpAddr4AndMask.addr = htonl(*((u_long *)&pAddrBytes[0]));
		fwpAddr4AndMask.mask = 0xffffffff << (32 - prefix);

		return this->Add(name, FWPM_LAYER_INBOUND_IPPACKET_V4, fwpFilterCondition, 1, weight, permit, persistent);
	}
	else
	{
		// IPv6 address
		FWP_V6_ADDR_AND_MASK fwpAddr6AndMask;
		::ZeroMemory(&fwpAddr6AndMask, sizeof(FWP_V6_ADDR_AND_MASK));

		fwpFilterCondition.conditionValue.type = FWP_V6_ADDR_MASK;
		fwpFilterCondition.conditionValue.v6AddrMask = &fwpAddr6AndMask;
		array<unsigned char>^ addrBytes = addr->GetAddressBytes();
		pin_ptr<unsigned char> pAddrBytes = &addrBytes[0];
		CopyMemory(&fwpAddr6AndMask.addr, pAddrBytes, 16);
		fwpAddr6AndMask.prefixLength = prefix;

		return this->Add(name, FWPM_LAYER_INBOUND_IPPACKET_V6, fwpFilterCondition, 1, weight, permit, persistent);
	}
}

UInt64 Firewall::Add(String^ name, IPAddress^ addrLow, IPAddress^ addrHigh, UInt64 weight, bool permit, bool persistent)
{
	OutputDebugString(L"Firewall::Add(name, addrLow, addrLast)");

	FWPM_FILTER_CONDITION fwpFilterCondition;
	FWP_RANGE fwpRange;

	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));
	::ZeroMemory(&fwpRange, sizeof(FWP_RANGE));

	if (addrLow->IsIPv4MappedToIPv6)
	{
		addrLow = addrLow->MapToIPv4();
	}
	if (addrHigh->IsIPv4MappedToIPv6)
	{
		addrHigh = addrHigh->MapToIPv4();
	}
	if (addrLow->AddressFamily != addrHigh->AddressFamily)
	{
		throw gcnew System::ArgumentException("Firewall::Add: Can't create range from IPv4 and IPv6 address");
	}

	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	fwpFilterCondition.matchType = FWP_MATCH_RANGE;
	fwpFilterCondition.conditionValue.type = FWP_RANGE_TYPE;
	if (addrLow->AddressFamily == Sockets::AddressFamily::InterNetwork)
	{
		// IPv4 address
		fwpFilterCondition.conditionValue.rangeValue = &fwpRange;
		fwpRange.valueLow.type = FWP_UINT32;
		fwpRange.valueHigh.type = FWP_UINT32;
		array<unsigned char>^ addrLowBytes = addrLow->GetAddressBytes();
		pin_ptr<unsigned char> pAddrLowBytes = &addrLowBytes[0];
		array<unsigned char>^ addrHighBytes = addrHigh->GetAddressBytes();
		pin_ptr<unsigned char> pAddrHighBytes = &addrHighBytes[0];
		fwpRange.valueLow.uint32 = htonl(*((u_long *)&pAddrLowBytes[0]));
		fwpRange.valueHigh.uint32 = htonl(*((u_long *)&pAddrHighBytes[0]));

		return this->Add(name, FWPM_LAYER_INBOUND_IPPACKET_V4, fwpFilterCondition, 1, weight, permit, persistent);
	}
	else
	{
		// IPv6 address
		fwpFilterCondition.conditionValue.rangeValue = &fwpRange;
		fwpRange.valueLow.type = FWP_BYTE_ARRAY16_TYPE;
		fwpRange.valueHigh.type = FWP_BYTE_ARRAY16_TYPE;
		array<unsigned char>^ addrLowBytes = addrLow->GetAddressBytes();
		pin_ptr<unsigned char> pAddrLowBytes = &addrLowBytes[0];
		array<unsigned char>^ addrHighBytes = addrHigh->GetAddressBytes();
		pin_ptr<unsigned char> pAddrHighBytes = &addrHighBytes[0];
		CopyMemory(&fwpRange.valueLow.byteArray16, pAddrLowBytes, 16);
		CopyMemory(&fwpRange.valueHigh.byteArray16, pAddrHighBytes, 16);

		return this->Add(name, FWPM_LAYER_INBOUND_IPPACKET_V6, fwpFilterCondition, 1, weight, permit, persistent);
	}
}

//UInt64 Firewall::Add(String^ name, List<Object^>^ rules) { return 0; }
//UInt64 Add(String^ name, char *data, UInt32 size);
UInt64 Firewall::AddIPv4(String^ name, FirewallConditions^ conditions, UInt64 weight, bool permit, bool persistent)
{
	OutputDebugString(L"Firewall::AddIPv4(String, FirewallConditions)");

	// Ignore empty list
	if (conditions->CountIPv4() == 0)
	{
		throw gcnew System::ArgumentException("Firewall::AddIPv4: no conditions");
	}

	return this->Add(name, conditions->LayerIPv4(), *conditions->GetIPv4(), conditions->CountIPv4(), weight, permit, persistent);
}
UInt64 Firewall::AddIPv6(String^ name, FirewallConditions^ conditions, UInt64 weight, bool permit, bool persistent)
{
	OutputDebugString(L"Firewall::AddIPv6(String, FirewallConditions)");

	// Ignore empty list
	if (conditions->CountIPv6() == 0)
	{
		throw gcnew System::ArgumentException("Firewall::AddIPv6: no conditions");
	}

	return this->Add(name, conditions->LayerIPv6(), *conditions->GetIPv6(), conditions->CountIPv6(), weight, permit, persistent);
}

UInt64 Firewall::Add(String^ name, const GUID &layerKey, FWPM_FILTER_CONDITION &fwpFilterCondition, UInt32 iFilterCondition, UInt64 weight, bool permit, bool persistent)
{
	OutputDebugString(L"Firewall::Add(String, &FWPM_FILTER_CONDITION)");

	// Add filter to block traffic from IP address
	DWORD rc = ERROR_SUCCESS;

	FWPM_FILTER fwpFilter;

	::ZeroMemory(&fwpFilter, sizeof(FWPM_FILTER));

	pin_ptr<const wchar_t> pName = PtrToStringChars(name);

	fwpFilter.layerKey = layerKey;
	fwpFilter.subLayerKey = F2BFW_SUBLAYER_KEY;
	fwpFilter.providerKey = (GUID*)&F2BFW_PROVIDER_KEY;
	fwpFilter.flags = FWPM_FILTER_FLAG_NONE;
	if (persistent)
		fwpFilter.flags |= FWPM_FILTER_FLAG_PERSISTENT;
	if (permit)
		fwpFilter.action.type = FWP_ACTION_PERMIT;
	else
		fwpFilter.action.type = FWP_ACTION_BLOCK;
	if (weight == 0)
		fwpFilter.weight.type = FWP_EMPTY; // auto-weight.
	else if (weight < 16)
	{
		fwpFilter.weight.type = FWP_UINT8;
		fwpFilter.weight.uint8 = (UINT8)weight;
	}
	else
	{
		fwpFilter.weight.type = FWP_UINT64;
		fwpFilter.weight.uint64 = &weight;
	}
	fwpFilter.displayData.name = (wchar_t *)pName;
	fwpFilter.numFilterConditions = iFilterCondition;
	fwpFilter.filterCondition = &fwpFilterCondition;

	UINT64 filterId = 0;
	rc = FwpmFilterAdd(*p_hEngineHandle, &fwpFilter, NULL, &filterId);
	if (rc != ERROR_SUCCESS) {
		throw gcnew FirewallException(rc, "Firewall::Add: FwpmFilterAdd failed (" + GetErrorText(rc) + ")");
	}
	else
	{
		OutputDebugString(L"Firewall::Add: FwpmFilterAdd OK");
	}

	return filterId;
}


// Remove filter with defined Id
void Firewall::Remove(UInt64 id)
{
	// Remove filter blocking traffic from IP address
	DWORD rc = ERROR_SUCCESS;
	FWPM_FILTER *pFilter = NULL;

	rc = FwpmFilterGetById(*p_hEngineHandle, id, &pFilter);
	if (rc != ERROR_SUCCESS) {
		throw gcnew FirewallException(rc, "Firewall::Remove: FwpmFilterGetById failed (" + GetErrorText(rc) + ")");
	}

	BOOL f2bGUIDs = ((pFilter->providerKey != NULL && IsEqualGUID(*pFilter->providerKey, F2BFW_PROVIDER_KEY)) || IsEqualGUID(pFilter->subLayerKey, F2BFW_SUBLAYER_KEY));
	if (pFilter != NULL)
	{
		FwpmFreeMemory((void **)&pFilter);
	}

	if (!f2bGUIDs)
	{
		OutputDebugString(L"Firewall::Remove:provider key and sublayer key doesn't match F2B GUIDs");
		return;
	}

	rc = FwpmFilterDeleteById(*p_hEngineHandle, id);
	if (rc != ERROR_SUCCESS) {
		throw gcnew FirewallException(rc, "Firewall::Remove: FwpmFilterDeleteById failed (" + GetErrorText(rc) + ")");
	}

	OutputDebugString(L"Firewall::Remove: FwpmFilterDeleteById OK");
}


// Remove all filter rules added by this module
void Firewall::Cleanup()
{
	OutputDebugString(L"Firewall::Cleanup");

	DWORD rc = ERROR_SUCCESS;

	// Use transaction to remove filters
	//rc = FwpmTransactionBegin(*p_hEngineHandle, 0);

	// Remove WFP filters related to our provider and sublayer
	HANDLE m_hFilterEnumHandle = NULL;
	//FWPM_FILTER_ENUM_TEMPLATE enumTemplate;
	FWPM_FILTER** pFilter = NULL;
	UINT32 nFilter;

	// template
	//ZeroMemory(&enumTemplate, sizeof(FWPM_FILTER_ENUM_TEMPLATE));
	//enumTemplate.providerKey = (GUID *)&F2BFW_PROVIDER_KEY;
	//enumTemplate.numFilterConditions = 0;
	//enumTemplate.actionMask = 0xFFFFFFFF;

	// filter
	rc = FwpmFilterCreateEnumHandle(*p_hEngineHandle, NULL, &m_hFilterEnumHandle);
	if (rc != ERROR_SUCCESS) {
		throw gcnew FirewallException(rc, "Firewall::Cleanup: FwpmFilterCreateEnumHandle failed (" + GetErrorText(rc) + ")");
	}

	rc = FwpmFilterEnum(*p_hEngineHandle, m_hFilterEnumHandle, INFINITE, &pFilter, &nFilter);
	if (rc != ERROR_SUCCESS) {
		FwpmFilterDestroyEnumHandle(*p_hEngineHandle, m_hFilterEnumHandle);
		throw gcnew FirewallException(rc, "Firewall::Cleanup: FwpmFilterEnum failed (" + GetErrorText(rc) + ")");
	}

	for (UINT32 i = 0; i < nFilter; i++)
	{
		FWPM_FILTER *f = pFilter[i];
		if (!((f->providerKey != NULL && IsEqualGUID(*f->providerKey, F2BFW_PROVIDER_KEY)) || IsEqualGUID(f->subLayerKey, F2BFW_SUBLAYER_KEY)))
			continue;

		//{ /// REMOVE
		//	PACL pDacl;
		//	PSECURITY_DESCRIPTOR securityDescriptor;
		//	rc = FwpmFilterGetSecurityInfoByKey(*p_hEngineHandle, NULL, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &securityDescriptor);
		//	PrintSD(securityDescriptor);
		//	FwpmFreeMemory((void **)&securityDescriptor);
		//}
		rc = FwpmFilterDeleteById(*p_hEngineHandle, f->filterId);
		if (rc != ERROR_SUCCESS) {
			OutputDebugString(FormatErrorText(L"Firewall::Cleanup: FwpmFilterDeleteById failed: ", rc));
			//throw new std::exception("FwpmFilterDeleteById failed");
		}
	}

	if (pFilter != NULL)
	{
		FwpmFreeMemory((void**)&pFilter);
	}

	rc = FwpmFilterDestroyEnumHandle(*p_hEngineHandle, m_hFilterEnumHandle);
	if (rc != ERROR_SUCCESS) {
		OutputDebugString(FormatErrorText(L"Firewall::Cleanup: FwpmFilterDestroyEnumHandle failed: ", rc));
		//throw gcnew FirewallException(rc, "Firewall::Cleanup: FwpmFilterDestroyEnumHandle failed (" + GetErrorText(rc) + ")");
	}

	// Use transaction to remove filters
	// rc = FwpmTransactionCommit0(engine);
}


// List all filter rules added by this module
Dictionary<UInt64, String^>^ Firewall::List(bool details)
{
	OutputDebugString(L"Firewall::List");

	DWORD rc = ERROR_SUCCESS;

	HANDLE m_hFilterEnumHandle = NULL;
	FWPM_FILTER** pFilter = NULL;
	UINT32 nFilter;

	// return only subset of filter rules
	FWPM_FILTER_ENUM_TEMPLATE enumTemplate;
	ZeroMemory(&enumTemplate, sizeof(FWPM_FILTER_ENUM_TEMPLATE));
	enumTemplate.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
	enumTemplate.providerKey = (GUID *)&F2BFW_PROVIDER_KEY;
	enumTemplate.actionMask = 0xFFFFFFFF;

	// filter
	rc = FwpmFilterCreateEnumHandle(*p_hEngineHandle, &enumTemplate, &m_hFilterEnumHandle);
	if (rc != ERROR_SUCCESS) {
		throw gcnew FirewallException(rc, "Firewall::List: FwpmFilterCreateEnumHandle failed (" + GetErrorText(rc) + ")");
	}

	rc = FwpmFilterEnum(*p_hEngineHandle, m_hFilterEnumHandle, INFINITE, &pFilter, &nFilter);
	if (rc != ERROR_SUCCESS) {
		FwpmFilterDestroyEnumHandle(*p_hEngineHandle, m_hFilterEnumHandle);
		throw gcnew FirewallException(rc, "Firewall::List: FwpmFilterEnum failed (" + GetErrorText(rc) + ")");
	}

	Dictionary<UInt64, String^>^ ret = gcnew Dictionary<UInt64, String^>();
	for (UINT32 i = 0; i < nFilter; i++)
	{
		FWPM_FILTER *f = pFilter[i];
		//if (f->providerKey == NULL)
		//	continue;
		//if (!IsEqualGUID(*f->providerKey, F2BFW_PROVIDER_KEY))
		//	continue;
		if (!IsEqualGUID(f->subLayerKey, F2BFW_SUBLAYER_KEY))
			continue;

		if (!details)
		{
			ret[f->filterId] = gcnew String(f->displayData.name);
			continue;
		}

		StringBuilder^ detail = gcnew StringBuilder();
		detail->Append("name[");
		detail->Append(gcnew String(f->displayData.name));
		detail->Append("]");
		detail->Append("/");
		// description
		if (f->displayData.description)
		{
			detail->Append("desc[");
			detail->Append(gcnew String(f->displayData.description));
			detail->Append("]");
			detail->Append("/");
		}
		// GUID
		detail->Append("GUID[");
		detail->Append(String::Format("{0:X08}-{1:X04}-{2:X04}-{3:X02}{4:X02}-{5:X02}{6:X02}{7:X02}{8:X02}{9:X02}{10:X02}",
			f->filterKey.Data1, f->filterKey.Data2, f->filterKey.Data3,
			f->filterKey.Data4[0], f->filterKey.Data4[1], f->filterKey.Data4[2], f->filterKey.Data4[3],
			f->filterKey.Data4[4], f->filterKey.Data4[5], f->filterKey.Data4[6], f->filterKey.Data4[7]));
		detail->Append("]");
		detail->Append("/");
		// action
		detail->Append("action[");
		switch (f->action.type)
		{
		case FWP_ACTION_BLOCK:
			detail->Append("block");
			break;
		case FWP_ACTION_PERMIT:
			detail->Append("permit");
			break;
		default:
			detail->Append("unknown");
			break;
		}
		detail->Append("]");
		detail->Append("/");
		// flags
		detail->Append("flags[");
		detail->Append(f->flags);
		detail->Append("]");
		detail->Append("/");
		// weight
		detail->Append("weight[");
		switch (f->weight.type)
		{
		case FWP_UINT8:
			detail->Append("range_index_");
			detail->Append(f->weight.uint8);
			break;
		case FWP_UINT64:
			detail->Append(*f->weight.uint64);
			break;
		case FWP_EMPTY:
			detail->Append("empty");
			break;
		default:
			detail->Append("unknown");
			break;
		}
		detail->Append("]");
		detail->Append("/");
        // effectiveWeight
		detail->Append("effectiveWeight[");
		switch (f->effectiveWeight.type)
		{
		case FWP_UINT8:
			detail->Append("range_index_");
			detail->Append(f->effectiveWeight.uint8);
			break;
		case FWP_UINT64:
			detail->Append(*f->effectiveWeight.uint64);
			break;
		case FWP_EMPTY:
			detail->Append("empty");
			break;
		default:
			detail->Append("unknown");
			break;
		}
		detail->Append("]");
		detail->Append("/");
		// conditions
		detail->Append("conditions[");
		for (UINT32 j = 0; j < f->numFilterConditions; j++)
		{
			FWPM_FILTER_CONDITION *c = &f->filterCondition[j];
			if (j != 0)
				detail->Append(",");
			detail->Append("(");
			detail->Append("fieldKey[");
			detail->Append(String::Format("{0:X08}-{1:X04}-{2:X04}-{3:X02}{4:X02}-{5:X02}{6:X02}{7:X02}{8:X02}{9:X02}{10:X02}",
				c->fieldKey.Data1, c->fieldKey.Data2, c->fieldKey.Data3,
				c->fieldKey.Data4[0], c->fieldKey.Data4[1], c->fieldKey.Data4[2], c->fieldKey.Data4[3],
				c->fieldKey.Data4[4], c->fieldKey.Data4[5], c->fieldKey.Data4[6], c->fieldKey.Data4[7]));
			detail->Append("],match[");
			switch (c->matchType)
			{
			case FWP_MATCH_EQUAL: detail->Append("equal"); break;
			case FWP_MATCH_GREATER: detail->Append("greater"); break;
			case FWP_MATCH_LESS: detail->Append("less"); break;
			case FWP_MATCH_GREATER_OR_EQUAL: detail->Append("greater_or_equal"); break;
			case FWP_MATCH_LESS_OR_EQUAL: detail->Append("less_or_equal"); break;
			case FWP_MATCH_RANGE: detail->Append("range"); break;
			case FWP_MATCH_FLAGS_ALL_SET: detail->Append("flags_all_set"); break;
			case FWP_MATCH_FLAGS_ANY_SET: detail->Append("flags_any_set"); break;
			case FWP_MATCH_FLAGS_NONE_SET: detail->Append("flags_none_set"); break;
			case FWP_MATCH_EQUAL_CASE_INSENSITIVE: detail->Append("equal_case_insensitive"); break;
			case FWP_MATCH_NOT_EQUAL: detail->Append("not_equal"); break;
			default: detail->Append("unknown"); break;
			}
			detail->Append("], value[");
			switch (c->conditionValue.type)
			{
			case FWP_EMPTY: detail->Append("empty"); break;
			case FWP_UINT8: detail->Append("uint8="); detail->Append(c->conditionValue.uint8); break;
			case FWP_UINT16: detail->Append("uint16="); detail->Append(c->conditionValue.uint16); break;
			case FWP_UINT32: detail->Append("uint32="); detail->Append(c->conditionValue.uint32); break;
			case FWP_UINT64: detail->Append("uint64="); detail->Append(*c->conditionValue.uint64); break;
			case FWP_INT8: detail->Append("int8="); detail->Append(c->conditionValue.int8); break;
			case FWP_INT16: detail->Append("int16="); detail->Append(c->conditionValue.int16); break;
			case FWP_INT32: detail->Append("int32="); detail->Append(c->conditionValue.int32); break;
			case FWP_INT64: detail->Append("int64="); detail->Append(*c->conditionValue.int64); break;
			case FWP_FLOAT: detail->Append("float="); detail->Append(c->conditionValue.float32); break;
			case FWP_DOUBLE: detail->Append("double="); detail->Append(*c->conditionValue.double64); break;
			case FWP_BYTE_ARRAY16_TYPE: detail->Append("byte16"); break;
			case FWP_BYTE_BLOB_TYPE: detail->Append("blob"); break;
			case FWP_SID: detail->Append("sid"); break;
			case FWP_SECURITY_DESCRIPTOR_TYPE: detail->Append("sd"); break;
			case FWP_TOKEN_INFORMATION_TYPE: detail->Append("token_info"); break;
			case FWP_TOKEN_ACCESS_INFORMATION_TYPE: detail->Append("token_access"); break;
			case FWP_UNICODE_STRING_TYPE: detail->Append("string"); break;
			case FWP_BYTE_ARRAY6_TYPE: detail->Append("byte6"); break;
			case FWP_V4_ADDR_MASK:
			{
				detail->Append("IPv4=");
				IPAddress^ addr = gcnew IPAddress(ntohl(c->conditionValue.v4AddrMask->addr));
				UINT8 prefix = 0;
				while (prefix < 32)
				{
					if ((ntohl(c->conditionValue.v4AddrMask->mask) & ((UINT32)1 << (31 - i))) == 0)
					{
						break;
					}
					prefix++;
				}
				detail->Append(addr->ToString());
				detail->Append("/");
				detail->Append(prefix);
				break;
			}
			case FWP_V6_ADDR_MASK:
			{
				detail->Append("IPv6=");
				array<Byte>^ buf = gcnew array<Byte>(16);
				Marshal::Copy((IntPtr)c->conditionValue.v6AddrMask->addr, buf, 0, 16);
				IPAddress^ addr = gcnew IPAddress(buf);
				UINT8 prefix = c->conditionValue.v6AddrMask->prefixLength;
				detail->Append(addr->ToString());
				detail->Append("/");
				detail->Append(prefix);
				break;
			}
			case FWP_RANGE_TYPE:
			{
				detail->Append("range=(");
#define XXXXXXXXXX(CV) \
				switch (CV.type) \
				{ \
				case FWP_EMPTY: detail->Append("empty"); break; \
				case FWP_UINT8: detail->Append("uint8="); detail->Append(CV.uint8); break; \
				case FWP_UINT16: detail->Append("uint16="); detail->Append(CV.uint16); break; \
				case FWP_UINT32: detail->Append("uint32="); detail->Append(CV.uint32); break; \
				case FWP_UINT64: detail->Append("uint64="); detail->Append(*CV.uint64); break; \
				case FWP_INT8: detail->Append("int8="); detail->Append(CV.int8); break; \
				case FWP_INT16: detail->Append("int16="); detail->Append(CV.int16); break; \
				case FWP_INT32: detail->Append("int32="); detail->Append(CV.int32); break; \
				case FWP_INT64: detail->Append("int64="); detail->Append(*CV.int64); break; \
				case FWP_FLOAT: detail->Append("float="); detail->Append(CV.float32); break; \
				case FWP_DOUBLE: detail->Append("double="); detail->Append(*CV.double64); break; \
				case FWP_BYTE_ARRAY16_TYPE: detail->Append("byte16"); break; \
				case FWP_BYTE_BLOB_TYPE: detail->Append("blob"); break; \
				case FWP_SID: detail->Append("sid"); break; \
				case FWP_SECURITY_DESCRIPTOR_TYPE: detail->Append("sd"); break; \
				case FWP_TOKEN_INFORMATION_TYPE: detail->Append("token_info"); break; \
				case FWP_TOKEN_ACCESS_INFORMATION_TYPE: detail->Append("token_access"); break; \
				case FWP_UNICODE_STRING_TYPE: detail->Append("string"); break; \
				case FWP_BYTE_ARRAY6_TYPE: detail->Append("byte6"); break; \
				case FWP_V4_ADDR_MASK: \
				{ \
					detail->Append("IPv4="); \
					IPAddress^ addr = gcnew IPAddress(ntohl(CV.uint32)); \
					detail->Append(addr->ToString()); \
					break; \
				} \
				case FWP_V6_ADDR_MASK: \
				{ \
					detail->Append("IPv6="); \
					array<Byte>^ buf = gcnew array<Byte>(16); \
					Marshal::Copy((IntPtr)CV.byteArray16, buf, 0, 16); \
					IPAddress^ addr = gcnew IPAddress(buf); \
					detail->Append(addr->ToString()); \
					break; \
				} \
				default: detail->Append("unknown"); break; \
				}

				XXXXXXXXXX(c->conditionValue.rangeValue->valueLow)
				detail->Append(",");
				XXXXXXXXXX(c->conditionValue.rangeValue->valueHigh)
				detail->Append(")");
				break;
			}
			default: detail->Append("unknown"); break;
			}
			detail->Append("])");
		}
		detail->Append("]");

		ret[f->filterId] = detail->ToString();
	}

	if (pFilter != NULL)
	{
		FwpmFreeMemory((void**)&pFilter);
	}

	rc = FwpmFilterDestroyEnumHandle(*p_hEngineHandle, m_hFilterEnumHandle);
	if (rc != ERROR_SUCCESS) {
		OutputDebugString(FormatErrorText(L"Firewall::List: FwpmFilterDestroyEnumHandle failed: ", rc));
		//throw gcnew FirewallException(rc, "Firewall::List: FwpmFilterDestroyEnumHandle failed (" + GetErrorText(rc) + ")");
	}

	return ret;
}



FirewallConditions::FirewallConditions()
{
	OutputDebugString(L"FirewallConditions::FirewallConditions");

	conditions4 = new std::vector<FWPM_FILTER_CONDITION>();
	conditions6 = new std::vector<FWPM_FILTER_CONDITION>();
	hasIPv4 = false;
	hasIPv6 = false;
	needTransportLayer = false;

	OutputDebugString(L"FirewallConditions::FirewallConditions OK");
}


FirewallConditions::~FirewallConditions()
{
	// clean up code to release managed resource
	OutputDebugString(L"FirewallConditions::~FirewallConditions");

	// call finalizer to release unmanaged resources
	this->!FirewallConditions();

	OutputDebugString(L"FirewallConditions::~FirewallConditions OK");
}


FirewallConditions::!FirewallConditions()
{
	// clean up code to release unmanaged resources
	OutputDebugString(L"FirewallConditions::!FirewallConditions");

	// release memory allocated in any Add method
	if (conditions4)
	{
		for (FWPM_FILTER_CONDITION cond : *conditions4)
		{
			FreeCondition(cond);
		}

		delete conditions4;
	}
	if (conditions6)
	{
		for (FWPM_FILTER_CONDITION cond : *conditions6)
		{
			FreeCondition(cond);
		}

		delete conditions6;
	}

	OutputDebugString(L"FirewallConditions::!FirewallConditions OK");
}


void FirewallConditions::FreeCondition(FWPM_FILTER_CONDITION &fwpFilterCondition)
{
	FWP_CONDITION_VALUE *cvalue = &fwpFilterCondition.conditionValue;
	FWP_MATCH_TYPE mtype = fwpFilterCondition.matchType;
	FWP_DATA_TYPE vtype = fwpFilterCondition.conditionValue.type;
	if (mtype == FWP_MATCH_EQUAL)
	{
		if (vtype == FWP_V4_ADDR_MASK)
		{
			delete cvalue->v4AddrMask;
		}
		else if (vtype == FWP_V6_ADDR_MASK)
		{
			delete cvalue->v6AddrMask;
		}
		else if (vtype == FWP_BYTE_ARRAY16_TYPE)
		{
			delete cvalue->byteArray16;
		}
	}
	else if (mtype == FWP_RANGE_TYPE)
	{
		if (cvalue->rangeValue->valueLow.type == FWP_BYTE_ARRAY16_TYPE)
		{
			delete cvalue->rangeValue->valueLow.byteArray16;
		}
		if (cvalue->rangeValue->valueHigh.type == FWP_BYTE_ARRAY16_TYPE)
		{
			delete cvalue->rangeValue->valueHigh.byteArray16;
		}
		delete cvalue->rangeValue;
	}
}


// Add new filtering rule condition
void FirewallConditions::Add(IPAddress^ addr)
{
	return this->Add(addr, 128);
}

void FirewallConditions::Add(IPAddress^ addr, int prefix)
{
	OutputDebugString(L"FirewallConditions::Add(addr, prefix)");

	if (addr->IsIPv4MappedToIPv6)
	{
		addr = addr->MapToIPv4();
		if (prefix >= 96)
		{
			prefix -= 96;
		}
	}

	FWPM_FILTER_CONDITION fwpFilterCondition;
	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));

	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	fwpFilterCondition.matchType = FWP_MATCH_EQUAL;
	if (addr->AddressFamily == Sockets::AddressFamily::InterNetwork)
	{
		// IPv4 address
		hasIPv4 = true;

		FWP_V4_ADDR_AND_MASK *fwpAddr4AndMask = new FWP_V4_ADDR_AND_MASK;
		::ZeroMemory(fwpAddr4AndMask, sizeof(FWP_V4_ADDR_AND_MASK));

		fwpFilterCondition.conditionValue.type = FWP_V4_ADDR_MASK;
		fwpFilterCondition.conditionValue.v4AddrMask = fwpAddr4AndMask;
		array<unsigned char>^ addrBytes = addr->GetAddressBytes();
		pin_ptr<unsigned char> pAddrBytes = &addrBytes[0];
		fwpAddr4AndMask->addr = htonl(*((u_long *)&pAddrBytes[0]));
		fwpAddr4AndMask->mask = 0xffffffff << (32 - prefix);

		conditions4->push_back(fwpFilterCondition);
	}
	else
	{
		// IPv6 address
		hasIPv6 = true;

		FWP_V6_ADDR_AND_MASK *fwpAddr6AndMask = new FWP_V6_ADDR_AND_MASK;
		::ZeroMemory(fwpAddr6AndMask, sizeof(FWP_V6_ADDR_AND_MASK));

		fwpFilterCondition.conditionValue.type = FWP_V6_ADDR_MASK;
		fwpFilterCondition.conditionValue.v6AddrMask = fwpAddr6AndMask;
		array<unsigned char>^ addrBytes = addr->GetAddressBytes();
		pin_ptr<unsigned char> pAddrBytes = &addrBytes[0];
		CopyMemory(&fwpAddr6AndMask->addr, pAddrBytes, 16);
		fwpAddr6AndMask->prefixLength = prefix;

		conditions6->push_back(fwpFilterCondition);
	}
}

void FirewallConditions::Add(IPAddress^ addrLow, IPAddress^ addrHigh)
{
	OutputDebugString(L"FirewallConditions::Add(addrLow, addrHigh)");

	if (addrLow->IsIPv4MappedToIPv6)
	{
		addrLow = addrLow->MapToIPv4();
	}
	if (addrHigh->IsIPv4MappedToIPv6)
	{
		addrHigh = addrHigh->MapToIPv4();
	}
	if (addrLow->AddressFamily != addrHigh->AddressFamily)
	{
		throw gcnew System::ArgumentException("Firewall::Add: Can't create range from IPv4 and IPv6 address");
	}

	array<unsigned char>^ addrLowBytes = addrLow->GetAddressBytes();
	array<unsigned char>^ addrHighBytes = addrHigh->GetAddressBytes();

	int addrSize = (addrLow->AddressFamily == Sockets::AddressFamily::InterNetwork ? 4 : 16);
	for (int i = 0; i < addrSize; i++)
	{
		if (addrLowBytes[i] > addrHighBytes[i])
		{
			throw gcnew System::ArgumentException("FirewallConditions::Add: Address range invalid (Low address is bigger then High address");
		}
		else if (addrLowBytes[i] < addrHighBytes[i])
		{
			break;
		}
	}

	FWPM_FILTER_CONDITION fwpFilterCondition;
	FWP_RANGE *fwpRange = new FWP_RANGE;
	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));
	::ZeroMemory(fwpRange, sizeof(FWP_RANGE));

	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	fwpFilterCondition.matchType = FWP_MATCH_RANGE;
	fwpFilterCondition.conditionValue.type = FWP_RANGE_TYPE;
	fwpFilterCondition.conditionValue.rangeValue = fwpRange;
	if (addrLow->AddressFamily == Sockets::AddressFamily::InterNetwork)
	{
		// IPv4 address
		hasIPv4 = true;

		pin_ptr<unsigned char> pAddrLowBytes = &addrLowBytes[0];
		pin_ptr<unsigned char> pAddrHighBytes = &addrHighBytes[0];

		fwpRange->valueLow.type = FWP_UINT32;
		fwpRange->valueHigh.type = FWP_UINT32;
		fwpRange->valueLow.uint32 = htonl(*((u_long *)&pAddrLowBytes[0]));
		fwpRange->valueHigh.uint32 = htonl(*((u_long *)&pAddrHighBytes[0]));

		conditions4->push_back(fwpFilterCondition);
	}
	else
	{
		// IPv6 address
		hasIPv6 = true;

		FWP_BYTE_ARRAY16 *fwpByteArray16Low = new FWP_BYTE_ARRAY16;
		FWP_BYTE_ARRAY16 *fwpByteArray16High = new FWP_BYTE_ARRAY16;
		::ZeroMemory(fwpByteArray16Low, sizeof(FWP_BYTE_ARRAY16));
		::ZeroMemory(fwpByteArray16High, sizeof(FWP_BYTE_ARRAY16));

		pin_ptr<unsigned char> pAddrLowBytes = &addrLowBytes[0];
		pin_ptr<unsigned char> pAddrHighBytes = &addrHighBytes[0];

		CopyMemory(fwpByteArray16Low, pAddrLowBytes, 16);
		CopyMemory(fwpByteArray16High, pAddrHighBytes, 16);

		fwpRange->valueLow.type = FWP_BYTE_ARRAY16_TYPE;
		fwpRange->valueHigh.type = FWP_BYTE_ARRAY16_TYPE;
		fwpRange->valueLow.byteArray16 = fwpByteArray16Low;
		fwpRange->valueHigh.byteArray16 = fwpByteArray16High;

		conditions6->push_back(fwpFilterCondition);
	}
}

void FirewallConditions::Add(short port)
{
	OutputDebugString(L"FirewallConditions::Add(port)");

	FWPM_FILTER_CONDITION fwpFilterCondition;
	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));

	// layerThis = FWPM_LAYER_INBOUND_TRANSPORT_V4 + FWPM_LAYER_INBOUND_TRANSPORT_V6;
	needTransportLayer = true;
	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
	fwpFilterCondition.matchType = FWP_MATCH_EQUAL;
	fwpFilterCondition.conditionValue.type = FWP_UINT16;
	fwpFilterCondition.conditionValue.uint16 = port;

	conditions4->push_back(fwpFilterCondition);
	conditions6->push_back(fwpFilterCondition);
}

void FirewallConditions::Add(short portLow, short portHigh)
{
	OutputDebugString(L"FirewallConditions::Add(portLow, portHigh)");

	if (portLow > portHigh)
	{
		throw gcnew System::ArgumentException("FirewallConditions::Add: Port range invalid (low port number is bigger then high port number");
	}

	FWPM_FILTER_CONDITION fwpFilterCondition;
	FWP_RANGE *fwpRange = new FWP_RANGE;
	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));
	::ZeroMemory(fwpRange, sizeof(FWP_RANGE));

	// layerThis = FWPM_LAYER_INBOUND_TRANSPORT_V4 + FWPM_LAYER_INBOUND_TRANSPORT_V6;
	needTransportLayer = true;
	fwpRange->valueLow.type = FWP_UINT16;
	fwpRange->valueLow.uint16 = portLow;
	fwpRange->valueHigh.type = FWP_UINT16;
	fwpRange->valueHigh.uint16 = portHigh;
	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
	fwpFilterCondition.matchType = FWP_MATCH_RANGE;
	fwpFilterCondition.conditionValue.type = FWP_RANGE_TYPE;
	fwpFilterCondition.conditionValue.rangeValue = fwpRange;

	conditions4->push_back(fwpFilterCondition);
	conditions6->push_back(fwpFilterCondition);
}

void FirewallConditions::Add(ProtocolType^ protocol)
{
	OutputDebugString(L"FirewallConditions::Add(protocol)");

	FWPM_FILTER_CONDITION fwpFilterCondition;
	::ZeroMemory(&fwpFilterCondition, sizeof(FWPM_FILTER_CONDITION));

	// layerThis = FWPM_LAYER_INBOUND_TRANSPORT_V4 + FWPM_LAYER_INBOUND_TRANSPORT_V6;
	needTransportLayer = true;
	fwpFilterCondition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	fwpFilterCondition.matchType = FWP_MATCH_EQUAL;
	fwpFilterCondition.conditionValue.type = FWP_UINT8;
	fwpFilterCondition.conditionValue.uint8 = Convert::ToByte(protocol);

	conditions4->push_back(fwpFilterCondition);
	conditions6->push_back(fwpFilterCondition);
}

		
		
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
	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		rc,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
		) > 0)
	{
		while (wcslen(lpMsgBuf) > 0 && (lpMsgBuf[wcslen(lpMsgBuf) - 1] == L' ' || lpMsgBuf[wcslen(lpMsgBuf) - 1] == L'\n' || lpMsgBuf[wcslen(lpMsgBuf) - 1] == L'\r'))
		{
			lpMsgBuf[wcslen(lpMsgBuf) - 1] = L'\0'; // remove new line character
		}
		swprintf(unknown, 1024, L"ERROR 0x%08x (%s)", rc, lpMsgBuf);
	}
	else
	{
		swprintf(unknown, 1024, L"Unrecognized ERROR 0x%08x", rc);
	}

	if (lpMsgBuf != NULL)
	{
		LocalFree(lpMsgBuf);
	}

	return unknown;
}


// Format WPF error message
static WCHAR * F2B::FormatErrorText(WCHAR * msg, DWORD rc)
{
	static WCHAR buf[1024];
	swprintf_s(buf, 1023, L"%s (%s)", msg, GetErrorTextOld(rc));
	return buf;
}


static String^ F2B::GetErrorText(DWORD rc)
{
	return gcnew String(GetErrorTextOld(rc));
}
