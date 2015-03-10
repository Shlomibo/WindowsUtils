using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Utilities;

namespace Windows
{
	/// <summary>
	/// Wraps unsafe pointers as disposable objects.
	/// </summary>
	public class UnmanagedBuffer : SafeObject<IntPtr>
	{
		#region Properties

		/// <summary>
		/// Gets the size of the buffer.
		/// </summary>
		public int? Size { get; private set; }
		#endregion

		#region Ctor

		/// <summary>
		/// Creates new UnmanagedBuffer for the specified pointer
		/// </summary>
		/// <param name="ptr">Pointer to the buffer.</param>
		public UnmanagedBuffer(IntPtr ptr) : base(ptr, pointer => Marshal.FreeHGlobal(pointer)) { }

		/// <summary>
		/// Creates new UnmanagedBuffer for the specified pointer
		/// </summary>
		/// <param name="ptr">Pointer to the buffer.</param>
		/// <param name="size">The size in bytes of the buffer.</param>
		public UnmanagedBuffer(IntPtr ptr, int size)
			: this(ptr)
		{
			this.Size = size;
		}

		/// <summary>
		/// Allocates buffer in the specified size, and creates new UnmanagedBuffer wrapper for it
		/// </summary>
		/// <param name="size">The size in bytes of the buffer to allocate</param>
		public UnmanagedBuffer(int size)
			: this(Marshal.AllocHGlobal(size))
		{
			this.Size = size;
		}

		/// <summary>
		/// Allocates buffer to hold the string in the specified character set, 
		/// and creates new UnmanagedBuffer wrapper for it
		/// </summary>
		/// <param name="str">The string to allocate in unmanaged memory</param>
		/// <param name="charset">The character set for the string</param>
		public UnmanagedBuffer(string str, CharSet charset)
			: this(AllocateString(str, charset))
		{
			switch (charset)
			{
				case CharSet.Ansi:

					this.Size = str.Length;
					break;

				case CharSet.Unicode:

					this.Size = str.Length * sizeof(char);
					break;

				case CharSet.Auto:
				case CharSet.None:
				default:

					this.Size = null;
					break;
			}
		}

		/// <summary>
		/// Allocates buffer to hold the string, and creates new UnmanagedBuffer wrapper for it
		/// </summary>
		/// <param name="str">The string to allocate in unmanaged memory</param>
		public UnmanagedBuffer(string str) : this(str, CharSet.Auto) { }

		/// <summary>
		/// Creates new UnmanagedBuffer for the specified pointer
		/// </summary>
		/// <param name="ptr">Pointer to the buffer.</param>
		public unsafe UnmanagedBuffer(void* ptr) : this((IntPtr)ptr) { }

		/// <summary>
		/// Creates new UnmanagedBuffer for the specified pointer.
		/// </summary>
		/// <param name="ptr">Pointer to the buffer.</param>
		/// <param name="size">The size in bytes of the buffer.</param>
		public unsafe UnmanagedBuffer(void* ptr, int size)
			: this(ptr)
		{
			this.Size = size;
		}
		#endregion

		#region Methods

		private static IntPtr AllocateString(string str, CharSet charset)
		{
			switch (charset)
			{
				case CharSet.Ansi:

					return Marshal.StringToHGlobalAnsi(str);

				case CharSet.Unicode:

					return Marshal.StringToHGlobalUni(str);

				case CharSet.Auto:
				default:

					return Marshal.StringToHGlobalAuto(str);
			}
		}

		/// <summary>
		/// Reallocates the buffer.
		/// </summary>
		/// <param name="newSize">The new size for the buffer.</param>
		public void Reallocate(int newSize)
		{
			this.Object = Marshal.ReAllocHGlobal(this.Object, (IntPtr)newSize);
			this.Size = newSize;
		}

		/// <summary>
		/// Copyies the data to the other buffer
		/// </summary>
		/// <param name="otherBuffer">The target buffer</param>
		/// <param name="bytesToCopy">The ammount of bytes to be copies.</param>
		public unsafe void CopyTo(UnmanagedBuffer otherBuffer, int bytesToCopy)
		{
			if ((this.Size < bytesToCopy) ||
				(otherBuffer.Size < bytesToCopy))
			{
				throw new ArgumentOutOfRangeException("Buffers are smaller than the copied size");
			}

			byte* source = (byte*)this;
			byte* target = (byte*)otherBuffer;

			for (int i = 0; i < bytesToCopy; i++)
			{
				target[i] = source[i];
			}
		}

		/// <summary>
		/// Copyies the data to the other buffer
		/// </summary>
		/// <param name="otherBuffer">The target buffer</param>
		public void CopyTo(UnmanagedBuffer otherBuffer)
		{
			if (!this.Size.HasValue || !otherBuffer.Size.HasValue)
			{
				throw new InvalidOperationException("Both buffer have to have explicit size");
			}

			int bytesToCopy = Math.Min(this.Size.Value, otherBuffer.Size.Value);

			CopyTo(otherBuffer, bytesToCopy);
		}

		/// <summary>
		/// Creates a new copy of the data in the buffer
		/// </summary>
		/// <param name="bytesToCopy">The ammount of bytes to be copies.</param>
		/// <returns>An UnmanagedBuffer which contain copy of the data in this buffer.</returns>
		public UnmanagedBuffer CreateCopy(int bytesToCopy)
		{
			var newBuffer = new UnmanagedBuffer(bytesToCopy);
			CopyTo(newBuffer);

			return newBuffer;
		}

		/// <summary>
		/// Creates a new copy of the data in the buffer
		/// </summary>
		/// <returns>An UnmanagedBuffer which contain copy of the data in this buffer.</returns>
		public UnmanagedBuffer CreateCopy()
		{
			if (!this.Size.HasValue)
			{
				throw new InvalidOperationException("Buffer have to have explicit size");
			}

			return CreateCopy(this.Size.Value);
		}

		/// <summary>
		/// Returns enumerable that enumerates the items in the buffer.
		/// </summary>
		/// <typeparam name="T">The type of the items in the buffer.</typeparam>
		/// <param name="count">The count of items in the buffer</param>
		/// <returns>Enumerable that enumerates the items in the buffer.</returns>
		public IEnumerable<T> AsEnumerable<T>(int count)
		{
			for (int offset = 0, i = 0;
				i < count;
				offset += Marshal.SizeOf(typeof(T)), i++)
			{
				yield return (T)Marshal.PtrToStructure(this.Object + offset, typeof(T));
			}
		}

		/// <summary>
		/// Returns enumeration of the elements in the buffer
		/// </summary>
		/// <typeparam name="T">The type of elements in the buffer</typeparam>
		/// <returns>Enumeration of the elements in the buffer</returns>
		public IEnumerable<T> AsEnumerable<T>()
		{
			if (!this.Size.HasValue)
			{
				throw new InvalidOperationException("Buffer have to have explicit size");
			}

			return AsEnumerable<T>(this.Size.Value / Marshal.SizeOf(typeof(T)));
		}

		/// <summary>
		/// Returns enumeration of the elements in the buffer.
		/// </summary>
		/// <typeparam name="T">The type of elements in the buffer</typeparam>
		/// <param name="endOfBufferMarker">The element in the end of the buffer.</param>
		/// <returns>Enumeration of the elements in the buffer, not including the endOfBuffer</returns>
		public IEnumerable<T> AsEnumerable<T>(T endOfBufferMarker)
		{
			for (int i = 0; true; i += Marshal.SizeOf(typeof(T)))
			{
				var element = (T)Marshal.PtrToStructure(this.Object + i, typeof(T));

				if (!element.Equals(endOfBufferMarker))
				{
					yield return element;
				}
				else
				{
					yield break;
				}
			}
		}

		/// <summary>
		/// Returns enumeration of the elements in the buffer.
		/// </summary>
		/// <typeparam name="T">The type of elements in the buffer</typeparam>
		/// <param name="endOfBufferMarkers">The elements sequence in the end of the buffer.</param>
		/// <returns>Enumeration of the elements in the buffer, not including the endOfBuffer</returns>
		public IEnumerable<T> AsEnumerable<T>(T[] endOfBufferMarkers)
		{
			if (endOfBufferMarkers == null)
			{
				throw new NullReferenceException(nameof(endOfBufferMarkers));
			}

			if (!endOfBufferMarkers.Any())
			{
				throw new ArgumentException(nameof(endOfBufferMarkers));
			}

			for (int i = 0; true; i += Marshal.SizeOf(typeof(T)))
			{
				var element = (T)Marshal.PtrToStructure(this.Object + i, typeof(T));

				if (!endOfBufferMarkers.Any(marker => object.Equals(element, marker)))
				{
					yield return element;
				}
				else
				{
					yield break;
				}
			}
		}
		#endregion

		#region Casts

		/// <summary>
		/// Implicit cast into IntPtr
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static implicit operator IntPtr(UnmanagedBuffer obj) =>
			obj.Object;

		/// <summary>
		/// Implicit cast into void*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe implicit operator void*(UnmanagedBuffer obj) =>
			(void*)obj.Object;

		/// <summary>
		/// Explicit cast into sbyte*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator sbyte*(UnmanagedBuffer obj) =>
			(sbyte*)obj.Object;

		/// <summary>
		/// Explicit cast into byte*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator byte*(UnmanagedBuffer obj) =>
			(byte*)obj.Object;

		/// <summary>
		/// Explicit cast into short*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator short*(UnmanagedBuffer obj) =>
			(short*)obj.Object;

		/// <summary>
		/// Explicit cast into ushort*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator ushort*(UnmanagedBuffer obj) =>
			(ushort*)obj.Object;

		/// <summary>
		/// Explicit cast into int*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator int*(UnmanagedBuffer obj) =>
			(int*)obj.Object;

		/// <summary>
		/// Explicit cast into uint*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator uint*(UnmanagedBuffer obj) =>
			(uint*)obj.Object;

		/// <summary>
		/// Explicit cast into long*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator long*(UnmanagedBuffer obj) =>
			(long*)obj.Object;

		/// <summary>
		/// Explicit cast into ulong*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator ulong*(UnmanagedBuffer obj) =>
			(ulong*)obj.Object;

		/// <summary>
		/// Explicit cast into char*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator char*(UnmanagedBuffer obj) =>
			(char*)obj.Object;

		/// <summary>
		/// Explicit cast into float*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator float*(UnmanagedBuffer obj) =>
			(float*)obj.Object;

		/// <summary>
		/// Explicit cast into double*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator double*(UnmanagedBuffer obj) =>
			(double*)obj.Object;

		/// <summary>
		/// Explicit cast into decimal*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator decimal*(UnmanagedBuffer obj) =>
			(decimal*)obj.Object;

		/// <summary>
		/// Explicit cast into bool*
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static unsafe explicit operator bool*(UnmanagedBuffer obj) =>
			(bool*)obj.Object;
		#endregion
	}

}
