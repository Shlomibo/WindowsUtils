using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Windows.Interop
{
	internal class Security
	{
		[DllImport("Advapi32.dll")]
		public static extern uint SetNamedSecurityInfo(
			string objectName,
			ObjectType type,
			uint scurityInfo,
			IntPtr ownerSid,
			IntPtr primaryGroupSid,
			IntPtr dacl,
			IntPtr sacl);

		[DllImport("Advapi32.dll")]
		public static extern uint GetNamedSecurityInfo(
			string objectName,
			ObjectType type,
			uint securityInfo,
			IntPtr ownerSid,
			IntPtr primaryGroupSid,
			IntPtr dacl,
			IntPtr sacl,
			IntPtr securityDescriptor);
	}

	internal enum ObjectType
	{
		SUnknown = 0,
		FileObject,
		Service,
		Printer,
		RegistryKey,
		LMShare,
		KernelObject,
		WindowObject,
		DSObject,
		DSObjectAkk,
		PrivderDefinedObject,
		WmiGuidObject,
		RegistryWow64_32Key
	}
}
