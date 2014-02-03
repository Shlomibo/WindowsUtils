using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Windows.Interop
{
	internal static class Windows
	{
		[DllImport("user32.dll")]
		public static extern uint RegisterWindowMessage(string message);

		[DllImport("user32.dll", SetLastError = true)]
		public static extern IntPtr SendMessage(IntPtr wHnd, uint message, UIntPtr wParam, IntPtr lParam);

		[DllImport("Kernel32.dll")]
		public static extern uint SleepEx(uint sleepMilliseconds, bool isAlertable);


		public static unsafe string GetStringFromPtr(sbyte* ptr)
		{
			return GetStringFromPtr(ptr, Encoding.UTF8, new sbyte[] { 0 });
		}

		public static unsafe string GetStringFromPtr(sbyte* ptr, Encoding encoding, sbyte[] teminator)
		{
			int length;

			for (length = 0; !IsTerminated(ptr + length, teminator); length++) ;

			var str = new string(ptr, 0, length, encoding);

			return str;
		}

		private static unsafe bool IsTerminated(sbyte* ptr, sbyte[] terminator)
		{
			bool isTerminated = true;

			for (int i = 0; (i < terminator.Length) && isTerminated; i++)
			{
				isTerminated |= ptr[i] == terminator[i];
			}

			return isTerminated;
		}
	}
}
