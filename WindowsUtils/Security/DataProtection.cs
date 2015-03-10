using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Windows.Security
{
	/// <summary>
	/// Provides managed access to DPAPI
	/// For more information on how to use, seach DPAPI, 
	/// or browse to http://msdn.microsoft.com/en-us/library/ms995355.aspx
	/// </summary>
	public static class DataProtection
	{
		#region Consts

		/// <summary>
		/// A prompt instance was provided, and UIForbidden flag was specified.
		/// </summary>
		public const int ERROR_PASSWORD_RESTRICTION = 0x52D;
		/// <summary>
		/// The default protection level configured of the host is higher than the current protection level 
		/// for the protected data byte array.
		/// </summary>
		public const int CRYPT_I_NEW_PROTECTION_REQUIRED = 0x00091012;
		/// <summary>
		/// The protected data is corrupted.
		/// </summary>
		public const int ERROR_INVALID_DATA = unchecked((int)0x8007000d);
		private const string DLL_CRYPT_32 = "Crypt32.dll";
		private const string DLL_KERNEL_32 = "Kernel32.dll";
		#endregion

		#region Methods

		// public unsafe static byte[] ProtectData(byte[] data,
		//		string description,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// =======================================================
		/// <summary>
		/// The ProtectData function performs encryption on the data in a byte array. 
		/// Typically, only a user with the same logon credential as the user who encrypted 
		/// the data can decrypt the data. 
		/// In addition, the encryption and decryption usually must be done on the same computer. 
		/// </summary>
		/// <param name="data">Contains the plaintext to be encrypted.</param>
		/// <param name="description">
		/// A string with a readable description of the data to be encrypted.
		/// This description string is included with the encrypted data.
		/// This parameter is optional and can be set to null.
		/// </param>
		/// <param name="optionalEntropy">
		/// A byte array that contains a password or other additional entropy used to encrypt the data.
		/// The byte array used in the encryption phase must also be used in the decryption phase.
		/// This parameter can be set to null for no additional entropy.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed,
		/// and what the content of those prompts should be. 
		/// This parameter can be set to null in both the encryption and decryption phases.
		/// </param>
		/// <param name="flags">
		/// This parameter can be one of the following DataProtectionFlags flags:
		/// UIForbidden, LocalMachine, Audit
		/// </param>
		/// <returns>A byte array that receives the encrypted data.</returns>
		public unsafe static byte[] ProtectData(byte[] data,
			string description,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			if (data == null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			string promptString = prompt != null
				? prompt.Message
				: null;

			fixed (byte* pDataIn = data)
			fixed (char* szDescription = description)
			fixed (byte* pOptionalEntrpy = optionalEntropy)
			fixed (char* szPrompt = promptString)
			{
				DataBlob dataIn = new DataBlob
				{
					data = pDataIn,
					size = (uint)data.Length,
				};

				DataBlob entropy;
				DataBlob* pEntropy = null;

				if (optionalEntropy != null)
				{
					entropy = new DataBlob
					{
						data = pOptionalEntrpy,
						size = (uint)optionalEntropy.Length,
					};

					pEntropy = &entropy;
				}

				PromptStruct promptStruct;
				PromptStruct* pPromptStruct = null;

				if (prompt != null)
				{
					promptStruct = new PromptStruct
					{
						hwndApp = prompt.AppHandle,
						prompt = szPrompt,
						promptFlags = (uint)prompt.Flags,
						size = (uint)sizeof(PromptStruct),
					};

					pPromptStruct = &promptStruct;
				}

				var dataOut = new DataBlob();

				try
				{
					if (!CryptProtectData(
						&dataIn,
						szDescription,
						pEntropy,
						IntPtr.Zero,
						pPromptStruct,
						(uint)flags,
						&dataOut))
					{
						throw new Win32Exception();
					}
					else
					{
						byte[] outArray = new byte[dataOut.size];

						Marshal.Copy((IntPtr)dataOut.data, outArray, 0, outArray.Length);

						return outArray;
					}
				}
				finally
				{
					Marshal.FreeHGlobal((IntPtr)dataOut.data);
				}
			}
		}

		// public static byte[] ProtectData(byte[] data,
		//		string description,
		//		string password,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// ==============================================
		/// <summary>
		/// The ProtectData function performs encryption on the data in a byte array. 
		/// Typically, only a user with the same logon credential as the user who encrypted 
		/// the data can decrypt the data. 
		/// In addition, the encryption and decryption usually must be done on the same computer. 
		/// </summary>
		/// <param name="data">Contains the plaintext to be encrypted.</param>
		/// <param name="description">
		/// A string with a readable description of the data to be encrypted.
		/// This description string is included with the encrypted data.
		/// This parameter is optional and can be set to null.
		/// </param>
		/// <param name="optionalPassword">
		/// A string that contains a password used to encrypt the data.
		/// The string used in the encryption phase must also be used in the decryption phase.
		/// This parameter can be set to null for no password protection.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed,
		/// and what the content of those prompts should be. 
		/// This parameter can be set to null in both the encryption and decryption phases.
		/// </param>
		/// <param name="flags">
		/// This parameter can be one of the following DataProtectionFlags flags:
		/// UIForbidden, LocalMachine, Audit
		/// </param>
		/// <returns>A byte array that receives the encrypted data.</returns>
		public static byte[] ProtectData(byte[] data,
			string description,
			string optionalPassword,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			return ProtectData(data, description, Encoding.Unicode.GetBytes(optionalPassword), prompt, flags);
		}

		// private unsafe static byte[] UnprotectData(
		//		byte[] protectedData,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags,
		//		out string description,
		//		bool shouldGetDescription)
		// ===========================================
		private unsafe static byte[] UnprotectData(
			byte[] protectedData,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags,
			out string description,
			bool shouldGetDescription)
		{
			description = null;

			if (protectedData == null)
			{
				throw new ArgumentNullException(nameof(protectedData));
			}

			string promptString = prompt != null
				? prompt.Message
				: null;

			fixed (byte* pProtected = protectedData)
			fixed (byte* pOptionalEntropy = optionalEntropy)
			fixed (char* szPromptString = promptString)
			{
				DataBlob dataIn = new DataBlob
				{
					data = pProtected,
					size = (uint)protectedData.Length,
				};

				char* szDescription = null;
				char** pszDescription = shouldGetDescription
					? &szDescription
					: null;

				DataBlob entropy;
				DataBlob* pEntropy = null;

				if (optionalEntropy != null)
				{
					entropy = new DataBlob
					{
						data = pOptionalEntropy,
						size = (uint)optionalEntropy.Length,
					};

					pEntropy = &entropy;
				}

				PromptStruct promptStruct;
				PromptStruct* pPromptStruct = null;

				if (prompt != null)
				{
					promptStruct = new PromptStruct
					{
						hwndApp = prompt.AppHandle,
						prompt = szPromptString,
						promptFlags = (uint)prompt.Flags,
						size = (uint)sizeof(PromptStruct),
					};

					pPromptStruct = &promptStruct;
				}

				var dataOut = new DataBlob();

				try
				{
					if (!CryptUnprotectData(
						&dataIn,
						pszDescription,
						pEntropy,
						IntPtr.Zero,
						pPromptStruct,
						(uint)flags,
						&dataOut))
					{
						throw new Win32Exception(Marshal.GetLastWin32Error());
					}
					else
					{
						if (shouldGetDescription && (szDescription != null))
						{
							description = new string(szDescription);
						}

						byte[] outArray = new byte[dataOut.size];
						Marshal.Copy((IntPtr)dataOut.data, outArray, 0, outArray.Length);

						return outArray;
					}
				}
				finally
				{
					Marshal.FreeHGlobal((IntPtr)dataOut.data);
					Marshal.FreeHGlobal((IntPtr)szDescription);
				}
			}
		}

		// public static byte[] UnprotectData(
		//		byte[] protectedData,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags,
		//		out string description)
		// ====================================
		/// <summary>
		/// The UnprotectData function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedData">A byte array that holds the encrypted data.</param>
		/// <param name="optionalEntropy">
		/// A byte array that contains a password or other additional entropy used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if an optional entropy byte array was used in the encryption phase,
		/// that same byte array must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <param name="description">
		/// A string-readable description of the encrypted data included with the encrypted data.
		/// This parameter can be set to null.
		/// </param>
		/// <returns>A byte array where the function stores the decrypted data.</returns>
		public static byte[] UnprotectData(
			byte[] protectedData,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags,
			out string description)
		{
			return UnprotectData(protectedData, optionalEntropy, prompt, flags, out description, true);
		}

		// public static byte[] UnprotectData(
		//		byte[] protectedData,
		//		string optionalPassword,
		//		Prompt prompt,
		//		DataProtectionFlags flags,
		//		out string description)
		// ====================================
		/// <summary>
		/// The UnprotectData function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedData">A byte array that holds the encrypted data.</param>
		/// <param name="optionalPassword">
		/// A string that contains a password used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if a password was used in the encryption phase,
		/// that same password must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <param name="description">
		/// A string-readable description of the encrypted data included with the encrypted data.
		/// This parameter can be set to null.
		/// </param>
		/// <returns>A byte array where the function stores the decrypted data.</returns>
		public static byte[] UnprotectData(
			byte[] protectedData,
			string optionalPassword,
			Prompt prompt,
			DataProtectionFlags flags,
			out string description)
		{
			return UnprotectData(
				protectedData,
				Encoding.Unicode.GetBytes(optionalPassword),
				prompt,
				flags,
				out description);
		}

		// public static byte[] UnprotectData(
		//		byte[] protectedData,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// =======================================
		/// <summary>
		/// The UnprotectData function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedData">A byte array that holds the encrypted data.</param>
		/// <param name="optionalEntropy">
		/// A byte array that contains a password or other additional entropy used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if an optional entropy byte array was used in the encryption phase,
		/// that same byte array must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <returns>A byte array where the function stores the decrypted data.</returns>
		public static byte[] UnprotectData(
			byte[] protectedData,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			string stub;

			return UnprotectData(protectedData, optionalEntropy, prompt, flags, out stub, false);
		}

		// public static byte[] UnprotectData(
		//		byte[] protectedData,
		//		string optionalPassword,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// =====================================
		/// <summary>
		/// The UnprotectData function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedData">A byte array that holds the encrypted data.</param>
		/// <param name="optionalPassword">
		/// A string that contains a password used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if a password was used in the encryption phase,
		/// that same password must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <returns>A byte array where the function stores the decrypted data.</returns>
		public static byte[] UnprotectData(
			byte[] protectedData,
			string optionalPassword,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			return UnprotectData(protectedData, Encoding.Unicode.GetBytes(optionalPassword), prompt, flags);
		}

		// public static byte[] ProtectString(
		//		string data,
		//		string description,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// ====================================
		/// <summary>
		/// The ProtectData function performs encryption on the string. 
		/// Typically, only a user with the same logon credential as the user who encrypted 
		/// the data can decrypt the data. 
		/// In addition, the encryption and decryption usually must be done on the same computer. 
		/// </summary>
		/// <param name="data">Contains the plaintext to be encrypted.</param>
		/// <param name="description">
		/// A string with a readable description of the data to be encrypted.
		/// This description string is included with the encrypted data.
		/// This parameter is optional and can be set to null.
		/// </param>
		/// <param name="optionalEntropy">
		/// A byte array that contains a password or other additional entropy used to encrypt the data.
		/// The byte array used in the encryption phase must also be used in the decryption phase.
		/// This parameter can be set to null for no additional entropy.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed,
		/// and what the content of those prompts should be. 
		/// This parameter can be set to null in both the encryption and decryption phases.
		/// </param>
		/// <param name="flags">
		/// This parameter can be one of the following DataProtectionFlags flags:
		/// UIForbidden, LocalMachine, Audit
		/// </param>
		/// <returns>A byte array that receives the encrypted data.</returns>
		public static byte[] ProtectString(
			string data,
			string description,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			byte[] binary = Encoding.Unicode.GetBytes(data);

			return ProtectData(binary, description, optionalEntropy, prompt, flags);
		}

		// public static byte[] ProtectString(
		//		string data,
		//		string description,
		//		string optionalPassword,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// =====================================
		/// <summary>
		/// The ProtectData function performs encryption on the string. 
		/// Typically, only a user with the same logon credential as the user who encrypted 
		/// the data can decrypt the data. 
		/// In addition, the encryption and decryption usually must be done on the same computer. 
		/// </summary>
		/// <param name="data">Contains the plaintext to be encrypted.</param>
		/// <param name="description">
		/// A string with a readable description of the data to be encrypted.
		/// This description string is included with the encrypted data.
		/// This parameter is optional and can be set to null.
		/// </param>
		/// <param name="optionalPassword">
		/// A string that contains a password used to encrypt the data.
		/// The string used in the encryption phase must also be used in the decryption phase.
		/// This parameter can be set to null for no password protection.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed,
		/// and what the content of those prompts should be. 
		/// This parameter can be set to null in both the encryption and decryption phases.
		/// </param>
		/// <param name="flags">
		/// This parameter can be one of the following DataProtectionFlags flags:
		/// UIForbidden, LocalMachine, Audit
		/// </param>
		/// <returns>A byte array that receives the encrypted data.</returns>
		public static byte[] ProtectString(
			string data,
			string description,
			string optionalPassword,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			return ProtectString(data, description, Encoding.Unicode.GetBytes(optionalPassword), prompt, flags);
		}

		// public static string UnprotectString(
		//		byte[] protectedString,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags,
		//		out string description)
		// ========================================
		/// <summary>
		/// The UnprotectString function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedString">A byte array that holds the encrypted string.</param>
		/// <param name="optionalEntropy">
		/// A byte array that contains a password or other additional entropy used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if an optional entropy byte array was used in the encryption phase,
		/// that same byte array must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <param name="description">
		/// A string-readable description of the encrypted data included with the encrypted data.
		/// This parameter can be set to null.
		/// </param>
		/// <returns>A string where the function stores the decrypted data.</returns>
		public static string UnprotectString(
			byte[] protectedString,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags,
			out string description)
		{
			byte[] binary = UnprotectData(protectedString, optionalEntropy, prompt, flags, out description);

			return Encoding.Unicode.GetString(binary);
		}

		// public static string UnprotectString(
		//		byte[] protectedString,
		//		string optionalPassword,
		//		Prompt prompt,
		//		DataProtectionFlags flags,
		//		out string description)
		// =====================================
		/// <summary>
		/// The UnprotectString function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedString">A byte array that holds the encrypted string.</param>
		/// <param name="optionalPassword">
		/// A string that contains a password used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if a password was used in the encryption phase,
		/// that same password must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <param name="description">
		/// A string-readable description of the encrypted data included with the encrypted data.
		/// This parameter can be set to null.
		/// </param>
		/// <returns>A string where the function stores the decrypted data.</returns>
		public static string UnprotectString(
			byte[] protectedString,
			string optionalPassword,
			Prompt prompt,
			DataProtectionFlags flags,
			out string description)
		{
			return UnprotectString(
				protectedString,
				Encoding.Unicode.GetBytes(optionalPassword),
				prompt,
				flags,
				out description);
		}

		// public static string UnprotectString(
		//		byte[] protectedString,
		//		byte[] optionalEntropy,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		/// <summary>
		/// The UnprotectString function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedString">A byte array that holds the encrypted string.</param>
		/// <param name="optionalEntropy">
		/// A byte array that contains a password or other additional entropy used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if an optional entropy byte array was used in the encryption phase,
		/// that same byte array must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <returns>A string where the function stores the decrypted data.</returns>
		public static string UnprotectString(
			byte[] protectedString,
			byte[] optionalEntropy,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			byte[] binary = UnprotectData(protectedString, optionalEntropy, prompt, flags);

			return Encoding.Unicode.GetString(binary);
		}

		// public static string UnprotectString(
		//		byte[] protectedString,
		//		string optionalPassword,
		//		Prompt prompt,
		//		DataProtectionFlags flags)
		// =====================================
		/// <summary>
		/// The UnprotectString function decrypts and does an integrity check of the data in a byte array.
		/// Usually, the only user who can decrypt the data is a user with the same logon credentials
		/// as the user who encrypted the data.
		/// In addition, the encryption and decryption must be done on the same computer.
		/// </summary>
		/// <param name="protectedString">A byte array that holds the encrypted string.</param>
		/// <param name="optionalPassword">
		/// A string that contains a password used when the data was encrypted.
		/// This parameter can be set to null;
		/// however, if a password was used in the encryption phase,
		/// that same password must be used for the decryption phase.
		/// </param>
		/// <param name="prompt">
		/// A Prompt class that provides information about where and when prompts are to be displayed
		/// and what the content of those prompts should be.
		/// This parameter can be set to null.
		/// </param>
		/// <param name="flags">
		/// A DataProtectionFlags value that specifies options for this function. 
		/// This parameter can one of the following flags:
		/// None, UIForbidden, VerifyProtection
		/// </param>
		/// <returns>A string where the function stores the decrypted data.</returns>
		public static string UnprotectString(
			byte[] protectedString,
			string optionalPassword,
			Prompt prompt,
			DataProtectionFlags flags)
		{
			return UnprotectString(protectedString, Encoding.Unicode.GetBytes(optionalPassword), prompt, flags);
		}

		// public static unsafe void SecureZeroMemory(byte[] memory)
		// =========================================================
		/// <summary>
		/// Fills a block of memory with zeros.
		/// </summary>
		/// <param name="memory">Array to fill with zeros.</param>
		[MethodImpl(MethodImplOptions.NoOptimization)]
		public static unsafe void SecureZeroMemory(byte[] memory)
		{
			fixed (byte* pMemory = memory)
			{
				ZeroMemory(pMemory, (uint)memory.Length);
			}
		}

		// public static unsafe void SecureZeroString(string @string)
		// ==========================================================
		/// <summary>
		/// Fills a string with zeros.
		/// 
		/// Be careful! this mutates the actual value of the string
		/// </summary>
		/// <param name="string">String to fill with zeros.</param>
		[MethodImpl(MethodImplOptions.NoOptimization)]
		public static unsafe void SecureZeroString(string @string)
		{
			fixed (char* szString = @string)
			{
				ZeroMemory(szString, (uint)@string.Length);
			}
		}
		#endregion

		#region P/Invoke

		[DllImport(DLL_CRYPT_32, SetLastError = true)]
		private static unsafe extern bool CryptProtectData(
			DataBlob* dataIn,
			char* dataDescription,
			DataBlob* optionalEntropy,
			IntPtr reserved,
			PromptStruct* prompt,
			uint flags,
			DataBlob* dataOut);

		[DllImport(DLL_CRYPT_32, SetLastError = true)]
		private static unsafe extern bool CryptUnprotectData(
			DataBlob* dataIn,
			char** dataDescription,
			DataBlob* optionalEntropy,
			IntPtr reserved,
			PromptStruct* prompt,
			uint flags,
			DataBlob* dataOut);

		[DllImport(DLL_KERNEL_32, EntryPoint="RtlZeroMemory", SetLastError=false)]
		internal extern static unsafe void ZeroMemory(void* memory, uint count);
		#endregion

		#region P/Invoke structures

		[StructLayout(LayoutKind.Sequential)]
		private unsafe struct DataBlob
		{
			public uint size;
			public byte* data;
		}

		[StructLayout(LayoutKind.Sequential)]
		private unsafe struct PromptStruct
		{
			public uint size;
			public uint promptFlags;
			public IntPtr hwndApp;
			public char* prompt;
		}
		#endregion
	}

	/// <summary>
	/// The Prompt class provides the text of a prompt and information about when and where
	/// that prompt is to be displayed when using the ProtectData and UnprotectData functions.
	/// </summary>
	public class Prompt
	{
		#region Properties

		// public PromptFlags Flags
		// ========================
		/// <summary>
		/// Gets or sets flags that indicate when prompts to the user are to be displayed.
		/// </summary>
		public PromptFlags Flags { get; set; }

		// public IntPtr AppHandle
		// =======================
		/// <summary>
		/// Gets or sets a window handle to the parent window.
		/// </summary>
		public IntPtr AppHandle { get; set; }

		// public string Prompt
		// ====================
		/// <summary>
		/// Gets or sets a string containing the text of a prompt to be displayed.
		/// </summary>
		public string Message { get; set; }
		#endregion

		#region Ctor

		// public Prompt()
		// ===============
		/// <summary>
		/// Creates new instance of the class
		/// </summary>
		public Prompt() { }

		// public Prompt(PromptFlags flags, IntPtr appHandle, string prompt)
		// =================================================================
		/// <summary>
		/// Creates new instance of the class
		/// </summary>
		/// <param name="flags">Flags that indicate when prompts to the user are to be displayed.</param>
		/// <param name="appHandle">A window handle to the parent window.</param>
		/// <param name="prompt">A string containing the text of a prompt to be displayed.</param>
		public Prompt(PromptFlags flags, IntPtr appHandle, string prompt)
			: this()
		{
			this.Flags = flags;
			this.AppHandle = appHandle;
			this.Message = prompt;
		}
		#endregion
	}

	#region Enums

	/// <summary>
	/// Flags that indicate when prompts to the user are to be displayed.
	/// </summary>
	[Flags]
	public enum PromptFlags : uint
	{
		/// <summary>Don't show the prompt</summary>
		None = 0,
		/// <summary>This flag is used to provide the prompt for the protect phase.</summary>
		OnProtect = 0x2,
		/// <summary>
		/// This flag can be combined with OnProtect to enforce the UI (user interface) policy of the caller.
		/// When UnprotectData is called, the PromptFlags specified in the ProtectData call are enforced.
		/// </summary>
		OnUnprotect = 0x1,
	}

	/// <summary>
	/// Flags for ProtectData and UnprotectData functions
	/// </summary>
	[Flags]
	public enum DataProtectionFlags : uint
	{
		/// <summary>No flags</summary>
		None = 0,
		/// <summary>
		/// This flag is used for remote situations where presenting a user interface (UI) is not an option.
		/// When this flag is set and a UI is specified for either the protect or unprotect operation,
		/// the operation fails and an exception throwns with the ERROR_PASSWORD_RESTRICTION (1325; 0x52D) code.
		/// </summary>
		UIForbidden = 0x1,
		/// <summary>
		/// When this flag is set, it associates the data encrypted with the current computer
		/// instead of with an individual user.
		/// Any user on the computer on which ProtectData is called can use UnprotectData to decrypt the data.
		/// </summary>
		LocalMachine = 0x4,
		/// <summary>This flag generates an audit on protect and unprotect operations.</summary>
		Audit = 0x10,
		/// <summary>
		/// This flag verifies the protection of a protected byte array.
		/// If the default protection level configured of the host is higher than the current
		/// protection level for the byte array, the function returns 
		/// CRYPT_I_NEW_PROTECTION_REQUIRED (593938; 0x00091012) to advise the caller 
		/// to again protect the plaintext contained in the byte array.
		/// </summary>
		VerifyProtection = 0x40,
	}
	#endregion
}
