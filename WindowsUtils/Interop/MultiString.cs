using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Windows.Interop
{
	/// <summary>
	/// Represents a multi-string
	/// </summary>
	public class MultiString : IList<string>
	{
		#region Consts

		private const int NOT_FOUND = -1;
		#endregion

		#region Fields

		private List<string> strings;
		#endregion

		#region Properties

		/// <summary>
		/// Gets or sets the string at the specified index.
		/// </summary>
		/// <param name="index">The zero-based index of the string to get or set.</param>
		/// <returns>The string at the specified index.</returns>
		public string this[int index]
		{
			get { return this.strings[index]; }
			set
			{
				string old = this[index];
				this.strings[index] = value;
				bool didChanged = false;

				try
				{
					if (OnChanging())
					{
						didChanged = true;
						OnChanged();
					}
					else
					{
						this.strings[index] = old;
					}
				}
				catch 
				{
					if (!didChanged)
					{
						this.strings[index] = old;
					}

					throw;
				}
			}
		}

		/// <summary>
		/// Gets the number of strings contained in the MultiString.
		/// </summary>
		public int Count
		{
			get { return this.strings.Count; }
		}

		bool ICollection<string>.IsReadOnly
		{
			get { return false; }
		}
		#endregion

		#region Events

		/// <summary>
		/// Occures after the MultiString has changed.
		/// </summary>
		public event EventHandler Changed = (s, e) => { };
		
		/// <summary>
		/// Occures after the MultiString has changed, but before the change is permanent.
		/// </summary>
		public event EventHandler<CancelEventArgs> Changing = (s, e) => { };
		#endregion

		#region Ctor

		/// <summary>
		/// Initializes a new instance of the MultiString class that is empty and has the default initial capacity.
		/// </summary>
		public MultiString()
		{
			this.strings = new List<string>();
		}

		/// <summary>
		/// Initializes a new instance of the MultiString class that is empty and has the specified initial capacity.
		/// </summary>
		/// <param name="capacity">The number of elements that the new MultiString can initially store.</param>
		public MultiString(int capacity)
		{
			this.strings = new List<string>(capacity);
		}

		/// <summary>
		/// Initializes a new instance of the MultiString class that contains strings copied from 
		/// the specified collection and has sufficient capacity to accommodate the number of strings copied.
		/// </summary>
		/// <param name="strings">The collection whose strings are copied to the new MultiString.</param>
		public MultiString(IEnumerable<string> strings)
		{
			this.strings = new List<string>(strings ?? new string[0]);
		}

		/// <summary>
		/// Initializes a new instance of the MultiString class that contains strings copied from 
		/// the native multi-string.
		/// </summary>
		/// <param name="mszMultiString">The native multi-string</param>
		/// <param name="bufferSize">The size of the buffer that holds the multi-string</param>
		public unsafe MultiString(char* mszMultiString, int bufferSize)
			: this(mszMultiString, bufferSize, true) { }

		/// <summary>
		/// Initializes a new instance of the MultiString class that contains strings copied from 
		/// the native multi-string.
		/// </summary>
		/// <param name="mszMultiString">The native multi-string</param>
		public unsafe MultiString(char* mszMultiString)
			: this(mszMultiString, int.MaxValue, false) { }

		/// <summary>
		/// Initializes a new instance of the MultiString class that contains strings copied from 
		/// the native multi-string format, stored in a managed String object.
		/// </summary>
		/// <param name="multiString">The managed String object that holds native multi-string.</param>
		public unsafe MultiString(string multiString)
		{
			fixed (char* mszMultiString = multiString)
			{
				var multiStringObj = new MultiString(mszMultiString, multiString.Length + 1);
				this.strings = multiStringObj.strings;
			}
		}


		private unsafe MultiString(char* mszMultiString, int bufferSize, bool hasBufferSize)
		{
			this.strings = new List<string>();

			if (mszMultiString != null)
			{
				string lastString;

				for (int index = 0; (index < bufferSize) &&
					((mszMultiString[index] != '\0') || (mszMultiString[index + 1] != '\0'));
					index += lastString.Length + 1)
				{
					lastString = hasBufferSize
						? CreateString(mszMultiString + index, bufferSize - index)
						: new string(mszMultiString + index);
					Add(lastString);
				}
			}
		}
		#endregion

		#region Methods

		private bool OnChanging()
		{
			var eventArgs = new CancelEventArgs();

			this.Changing(this, eventArgs);

			return !eventArgs.Canceled;
		}

		private void OnChanged()
		{
			this.Changed(this, EventArgs.Empty);
		}

		private unsafe string CreateString(char* szString, int maxCount)
		{
			var newStr = new StringBuilder(maxCount);

			for (int i = 0; (i < maxCount) && (szString[i] != '\0'); i++)
			{
				newStr.Append(szString[i]);
			}

			return newStr.ToString();
		}

		/// <summary>
		/// Determines the index of a specific string in the MultiString.
		/// </summary>
		/// <param name="str">The string to locate in the MultiString.</param>
		/// <returns>The index of string if found in the list; otherwise, -1.</returns>
		public int IndexOf(string str)
		{
			int index = NOT_FOUND;

			for (int i = 0; i < this.strings.Count; i++)
			{
				if (this.strings[i].ToString() == str)
				{
					index = i;
					break;
				}
			}

			return index;
		}

		/// <summary>
		/// Removes the MultiSting string at the specified index.
		/// </summary>
		/// <param name="index">The zero-based index of the string to remove.</param>
		public void RemoveAt(int index)
		{
			string old = this[index];
			this.strings.RemoveAt(index);
			bool didChanged = false;

			try
			{
				if (OnChanging())
				{
					didChanged = true;
					OnChanged();
				}
				else
				{
					this.strings.Insert(index, old);
				}
			}
			catch
			{
				if (!didChanged)
				{
					this.strings.Insert(index, old); 
				}

				throw;
			}
		}

		/// <summary>
		/// Inserts a string to the MultiString at the specified index.
		/// </summary>
		/// <param name="index">The zero-based index at which string should be inserted.</param>
		/// <param name="str">The string to insert into the MultiString.</param>
		public void Insert(int index, string str)
		{
			this.strings.Insert(index, str);
			bool didChanged = false;

			try
			{
				if (OnChanging())
				{
					didChanged = true;
					OnChanged();
				}
				else
				{
					this.strings.RemoveAt(index);
				}
			}
			catch 
			{
				if (!didChanged)
				{
					this.strings.RemoveAt(index);
				}

				throw;
			}
		}

		/// <summary>
		/// Adds a string to the MultiString. 
		/// </summary>
		/// <param name="str">The string to add to the MultiString.</param>
		public void Add(string str)
		{
			this.strings.Add(str);
			bool didChanged = false;

			try
			{
				if (OnChanging())
				{
					didChanged = true;
					OnChanged();
				}
				else
				{
					this.strings.RemoveAt(this.Count - 1);
				}
			}
			catch 
			{
				if (!didChanged)
				{
					this.strings.RemoveAt(this.Count - 1);
				}

				throw;
			}
		}

		/// <summary>
		/// Removes all items from the MultiString.
		/// </summary>
		public void Clear()
		{
			List<string> old = this.strings;
			this.strings = new List<string>(this.strings.Capacity);
			bool didChanged = false;

			try
			{
				if (OnChanging())
				{
					didChanged = true;
					OnChanged();
				}
				else
				{
					this.strings = old;
				}
			}
			catch 
			{
				if (!didChanged)
				{
					this.strings = old;
				}

				throw;
			}
		}

		/// <summary>
		/// Determines whether the MultiString contains a specific string.
		/// </summary>
		/// <param name="str">The string to locate in the MultiString.</param>
		/// <returns>true if item is found in the MultiString; otherwise, false.</returns>
		public bool Contains(string str)
		{
			return this.strings.Contains(str);
		}

		/// <summary>
		/// Copies the string of the MultiString to an Array, starting at a particular Array index.
		/// </summary>
		/// <param name="array">
		/// The one-dimensional Array that is the destination of the elements copied from MultiString.
		/// The Array must have zero-based indexing.
		/// </param>
		/// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
		public void CopyTo(string[] array, int arrayIndex)
		{
			for (int i = 0; i < this.Count; i++)
			{
				array[i + arrayIndex] = this[i];
			}
		}

		/// <summary>
		/// Removes the first occurrence of a specific string from the MultiString. 
		/// </summary>
		/// <param name="str">The string to remove from the MultiString.</param>
		/// <returns>
		/// true if string was successfully removed from the MultiString; otherwise, false. 
		/// This method also returns false if string is not found in the original MultiString.
		/// </returns>
		public bool Remove(string str)
		{
			int indexOf = IndexOf(str);
			bool didRemoved = this.strings.Remove(str);;
			bool didChanged = false;

			try
			{
				if (OnChanging())
				{
					didChanged = true;
					OnChanged();
				}
				else if (didRemoved)
				{
					didRemoved = false;
					this.strings.Insert(indexOf, str);
				}
			}
			catch 
			{
				if (!didChanged)
				{
					didRemoved = false;
					this.strings.Insert(indexOf, str);
				}

				throw;
			}

			return didRemoved;
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return (this as IEnumerable<string>).GetEnumerator();
		}

		IEnumerator<string> IEnumerable<string>.GetEnumerator()
		{
			return this.strings.GetEnumerator();
		}

		/// <summary>
		/// Returns a string that represents the current object.
		/// </summary>
		/// <returns>A string that represents the current object.</returns>
		public override string ToString()
		{
			return string.Join("\0", this) + "\0";
		}
		#endregion
	}

	/// <summary>
	/// An event args that provide canceling capability.
	/// </summary>
	public class CancelEventArgs : EventArgs
	{
		#region Properties

		/// <summary>
		/// Gets or sets whether the event should be canceled
		/// </summary>
		public bool Canceled { get; set; }
		#endregion

		#region Ctor

		/// <summary>
		/// Creates new instance
		/// </summary>
		public CancelEventArgs() { }

		/// <summary>
		/// Creates new instance, and prividing default value for cancelation
		/// </summary>
		/// <param name="canceled">true if the event should be canceled by default; otherwise false.</param>
		public CancelEventArgs(bool canceled)
			: this()
		{
			this.Canceled = canceled;
		}
		#endregion
	}
}
