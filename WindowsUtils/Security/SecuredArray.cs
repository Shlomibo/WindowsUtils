using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Windows.Security
{
	/// <summary>
	/// Represents an array which its memory is zeroed when disposed
	/// </summary>
	/// <typeparam name="T"></typeparam>
	public class SecuredArray<T> : IList<T>, IDisposable
		where T : struct
	{
		#region Consts

		/// <summary>
		/// Index which is returned is the item is not in the array
		/// </summary>
		public const int NOT_FOUND = -1;
		#endregion

		#region Fields

		private IntPtr pointer = IntPtr.Zero;
		private int length;
		private readonly int @sizeof = Marshal.SizeOf(typeof(T));
		private readonly int bytesCount;

		private readonly HashSet<Type> allowedTypes = new HashSet<Type>(new Type[]
		{
			typeof(sbyte),
			typeof(byte),
			typeof(short),
			typeof(ushort),
			typeof(int),
			typeof(uint),
			typeof(long),
			typeof(ulong),
			typeof(char),
			typeof(float),
			typeof(double),
			typeof(decimal),
			typeof(bool),
		});
		#endregion

		#region Properties

		// public bool IsDisposed 
		// ======================
		/// <summary>
		/// Gets value that indicates if the object is disposed
		/// </summary>
		public bool IsDisposed { get; protected set; }

		// public T this[int index]
		// ========================
		/// <summary>
		/// Gets or sets an item in the array
		/// </summary>
		/// <param name="index">The index of the item</param>
		/// <returns>The item in the index</returns>
		public T this[int index]
		{
			get
			{
				CheckBounds(index);

				return (T)Marshal.PtrToStructure(PointerTo(index), typeof(T));
			}
			set
			{
				CheckBounds(index);

				Marshal.StructureToPtr(value, PointerTo(index), false);
			}
		}

		// public int Length
		// =================
		/// <summary>
		/// Gets the size of the array
		/// </summary>
		public int Length => ThrowIfDisposed(() => this.length);

		// int ICollection<T>.Count
		// ========================
		int ICollection<T>.Count => this.Length;

		// bool ICollection<T>.IsReadOnly
		// ==============================
		bool ICollection<T>.IsReadOnly => ThrowIfDisposed(() => false);
		#endregion

		#region Ctor

		// public SecuredArray(int length)
		// ===============================
		/// <summary>
		/// Creates new instance of the class
		/// </summary>
		/// <param name="length">The size of the array</param>
		public SecuredArray(int length)
		{
			CheckType();

			this.length = length;
			this.bytesCount = this.length * this.@sizeof;
			this.pointer = Marshal.AllocHGlobal(this.bytesCount);
			SecureZeroArray();
		}

		// public SecuredArray(T[] array)
		// ==============================
		/// <summary>
		/// Creates new instance of the class
		/// </summary>
		/// <param name="array">Array to initialize from</param>
		public SecuredArray(T[] array)
			: this(array.Length)
		{
			for (int i = 0; i < array.Length; i++)
			{
				this[i] = array[i];
			}
		}

		// ~SecuredArray()
		// ===============
		/// <summary>
		/// Finallize the object
		/// </summary>
		~SecuredArray()
		{
			Dispose(false);
		}
		#endregion

		#region Methods

		// private IntPtr PointerTo(int index)
		// ===================================
		/// <summary>
		/// Calculates the poiner to the given index in the array
		/// </summary>
		/// <param name="index">The index to calculate</param>
		/// <returns>Pointer to the given index</returns>
		protected IntPtr PointerTo(int index) =>
			this.pointer + (index * this.@sizeof);

		// private void ThrowIfDisposed()
		// ==============================
		private void ThrowIfDisposed()
		{
			if (this.IsDisposed)
			{
				throw new ObjectDisposedException($"The '{nameof(SecuredArray<T>)}' is disposed", (Exception)null);
			}
		}

		private TReturned ThrowIfDisposed<TReturned>(Func<TReturned> func)
		{
			Debug.Assert(func != null, $"{nameof(func)} is null.");
			ThrowIfDisposed();
			return func();
		}

		// protected virtual void Dispose(bool disposing)
		// ==============================================
		/// <summary>
		/// Disposes the object
		/// </summary>
		/// <param name="disposing">Value that indicates if the object is disposed properly</param>
		protected virtual void Dispose(bool disposing)
		{
			GC.SuppressFinalize(this);
			SecureZeroArray();
			Marshal.FreeHGlobal(this.pointer);
			this.pointer = IntPtr.Zero;
			this.length = 0;
			this.IsDisposed = true;
		}

		// public unsafe void SecureZeroArray()
		// ====================================
		/// <summary>
		/// Zeros all bytes in the array
		/// </summary>
		public unsafe void SecureZeroArray()
		{
			ThrowIfDisposed();
			DataProtection.ZeroMemory((void*)this.pointer, (uint)this.bytesCount);
		}

		// protected virtual void CheckBounds(int index)
		// =============================================
		/// <summary>
		/// Throws exception if the index is outside the bounds of the array
		/// </summary>
		/// <param name="index"></param>
		protected virtual void CheckBounds(int index)
		{
			ThrowIfDisposed();

			if ((index < 0) || (index >= this.length))
			{
				throw new IndexOutOfRangeException();
			}
		}

		// protected virtual void CheckType()
		// ==================================
		/// <summary>
		/// Checks if the type of the items in the array is valid
		/// </summary>
		protected virtual void CheckType()
		{
			if (!CheckType(typeof(T)))
			{
				throw new InvalidTypeException(typeof(T));
			}
		}

		// private bool CheckType(Type type)
		// =================================
		private bool CheckType(Type type)
		{
			bool isOk = false;

			if (type.IsPointer || type.IsEnum)
			{
				isOk = true;
			}
			else if (type.IsValueType)
			{
				isOk = this.allowedTypes.Contains(type);

				if (!isOk)
				{
					isOk = type.GetFields(BindingFlags.NonPublic | BindingFlags.Instance)
							   .All(field => field.IsLiteral || CheckType(field.FieldType));
				}
			}

			return isOk;
		}

		// public int IndexOf(T item)
		// ==========================
		/// <summary>
		/// Determines the index of a specific item in the SecuredArray&lt;T&gt;.
		/// </summary>
		/// <param name="item">The object to locate in the SecuredArray&lt;T&gt;.</param>
		/// <returns>The index of item if found in the list; otherwise, -1.</returns>
		public int IndexOf(T item) =>
			ThrowIfDisposed(() => this.Select((String, Index) => new { String, Index })
									  .Where(element => object.Equals(item, element.String))
									  .Select(element => (int?)element.Index)
									  .FirstOrDefault() ?? NOT_FOUND);

		// void IList<T>.Insert(int index, T item)
		// =======================================
		void IList<T>.Insert(int index, T item)
		{
			throw new NotSupportedException();
		}

		// void IList<T>.RemoveAt(int index)
		// =================================
		void IList<T>.RemoveAt(int index)
		{
			throw new NotSupportedException();
		}

		// void ICollection<T>.Add(T item)
		// ===============================
		void ICollection<T>.Add(T item)
		{
			throw new NotSupportedException();
		}

		// void ICollection<T>.Clear()
		// ===========================
		void ICollection<T>.Clear()
		{
			throw new NotSupportedException();
		}

		// public bool Contains(T item)
		// ============================
		/// <summary>
		/// Determines whether the SecuredArray&lt;T&gt; contains a specific value.
		/// </summary>
		/// <param name="item">The object to locate in the SecuredArray&lt;T&gt;.</param>
		/// <returns>true if item is found in the SecuredArray&lt;T&gt;; otherwise, false.</returns>
		public bool Contains(T item) =>
			ThrowIfDisposed(() => this.IndexOf(item) != NOT_FOUND);
		
		// public void CopyTo(T[] array, int arrayIndex)
		// =============================================
		/// <summary>
		/// Copies the elements of the SecuredArray&lt;T&gt; to an Array, starting at a particular Array index.
		/// </summary>
		/// <param name="array">
		/// The one-dimensional Array that is the destination of the elements copied from SecuredArray&lt;T&gt;.
		/// The Array must have zero-based indexing.
		/// </param>
		/// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
		public void CopyTo(T[] array, int arrayIndex)
		{
			ThrowIfDisposed();

			if ((arrayIndex < 0) || (arrayIndex >= array.Length))
			{
				throw new ArgumentOutOfRangeException(nameof(arrayIndex));
			}

			if (arrayIndex > array.Length - this.Length)
			{
				throw new ArgumentException();
			}

			if (array == null)
			{
				throw new ArgumentNullException(nameof(array));
			}

			foreach (var element in this.Select((String, Index) => new { String, Index }))
			{
				array[arrayIndex + element.Index] = element.String;
			}
		}

		// bool ICollection<T>.Remove(T item)
		// ==================================
		bool ICollection<T>.Remove(T item)
		{
			throw new NotSupportedException();
		}

		// IEnumerator<T> IEnumerable<T>.GetEnumerator()
		// =============================================
		IEnumerator<T> IEnumerable<T>.GetEnumerator()
		{
			ThrowIfDisposed();

			for (int i = 0; i < this.length; i++)
			{
				yield return this[i];
			}
		}

		// IEnumerator IEnumerable.GetEnumerator()
		// =======================================
		IEnumerator IEnumerable.GetEnumerator()
		{
			return (this as IEnumerable<T>).GetEnumerator();
		}

		// public void Dispose()
		// =====================
		/// <summary>
		/// Disposes the object
		/// </summary>
		public void Dispose()
		{
			Dispose(true);
		}

		// private SecuredArray<T> Copy(int size)
		// ======================================
		private SecuredArray<T> Copy(int size)
		{
			ThrowIfDisposed();
			var newArray = new SecuredArray<T>(size);
			int length = Math.Min(this.Length, size);

			for (int i = 0; i < length; i++)
			{
				newArray[i] = this[i];
			}

			return newArray;
		}

		// public SecuredArray<T> Copy()
		// =============================
		/// <summary>
		/// Copies the items in the array to a new SecuredArray&lt;T&gt; object.
		/// </summary>
		/// <returns>A new SecuredArray&lt;T&gt; which contains copy of the items in this array</returns>
		public SecuredArray<T> Copy()
		{
			return Copy(this.Length);
		}

		// public void Reallocate(int newSize)
		// ===================================
		/// <summary>
		/// Resize the SecuredArray&lt;T&gt;.
		/// </summary>
		/// <param name="newSize">The new size for the SecuredArray&lt;T&gt;</param>
		public void Reallocate(int newSize)
		{
			SecuredArray<T> recreated = Copy(newSize);
			Dispose();
			this.IsDisposed = false;
			this.pointer = recreated.pointer;
			this.length = recreated.length;
			GC.SuppressFinalize(recreated);
			GC.ReRegisterForFinalize(this);
		}
		#endregion
	}

	/// <summary>
	/// Exception that throwns when to try to create SecuredArray&lt;T&gt; with invalid type
	/// </summary>
	[Serializable]
	public class InvalidTypeException : Exception
	{
		#region Consts

		private const string DEFAULT_MSG_FORMAT = @"The type '{0}' is invalid for safe array.
Only sbyte, byte, short, ushort, int, uint, long, ulong, char, float, double, decimal, bool, enums, pointers " +
			"or structures which cotains only valid types are allowed";
		private const string SRL_TYPE = "InvalidTypeException.Type";
		#endregion

		#region Properties

		// public Type Type 
		// ================
		/// <summary>
		/// Gets the type which is invalid for usage in SecuredArray&lt;T&gt;.
		/// </summary>
		public Type Type { get; }
		#endregion

		#region Ctor

		// public InvalidTypeException(Type type)
		// ======================================
		/// <summary>
		/// Creates new instance of the exception
		/// </summary>
		/// <param name="type">The type which is invalid for usage in SecuredArray&lt;T&gt;.</param>
		public InvalidTypeException(Type type)
			: base(string.Format(DEFAULT_MSG_FORMAT, type.FullName))
		{
			if (type == null)
			{
				throw new NullReferenceException(nameof(type));
			}

			this.Type = type;
		}

		// public InvalidTypeException(Type type, Exception inner)
		// =======================================================
		/// <summary>
		/// Creates new instance of the exception
		/// </summary>
		/// <param name="type">The type which is invalid for usage in SecuredArray&lt;T&gt;.</param>
		/// <param name="inner">
		/// The exception that is the cause of the current exception, 
		/// or a null reference (Nothing in Visual Basic) if no inner exception is specified.
		/// </param>
		public InvalidTypeException(Type type, Exception inner)
			: base(string.Format(DEFAULT_MSG_FORMAT, type.FullName), inner)
		{
			if (type == null)
			{
				throw new NullReferenceException(nameof(type));
			}

			this.Type = type;
		}

		// protected InvalidTypeException(
		//	  SerializationInfo info,
		//	  StreamingContext context)
		// ================================
		/// <summary>
		/// Initializes a new instance of the Exception class with serialized data.
		/// </summary>
		/// <param name="info">
		/// The SerializationInfo that holds the serialized object
		/// data about the exception being thrown.
		/// </param>
		/// <param name="context">
		/// The StreamingContext that contains contextual information
		/// about the source or destination.
		/// </param>
		protected InvalidTypeException(
		  SerializationInfo info,
		  StreamingContext context)
			: base(info, context)
		{
			this.Type = (Type)info.GetValue(SRL_TYPE, typeof(Type));
		}
		#endregion

		#region Methods

		// public override void GetObjectData(SerializationInfo info, StreamingContext context)
		// ====================================================================================
		/// <summary>
		/// When overridden in a derived class, sets the SerializationInfo with information about the exception.
		/// </summary>
		/// <param name="info">
		/// The SerializationInfo that holds the serialized object data about the exception being thrown.
		/// </param>
		/// <param name="context">
		/// The StreamingContext that contains contextual information about the source or destination.
		/// </param>
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
			info.AddValue(SRL_TYPE, this.Type);
		}
		#endregion
	}
}
