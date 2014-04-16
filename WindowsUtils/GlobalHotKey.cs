using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Utilities.Extansions.Enum;
using Utilities.TypeEditors;
using System.Drawing.Design;
using System.ComponentModel.Design;

namespace Utilities.Windows
{
	/// <summary>
	/// A components to register global hot key.
	/// </summary>
	public partial class GlobalHotKey : Component, IMessageFilter
	{
		#region Consts

		private const int WM_HOTKEY = 0x0312;

		private const string USER32 = "user32.dll";
		private const string KERNEL32 = "kernel32.dll";
		#endregion

		#region Fields

		private int id;
		private IntPtr hWnd;
		private bool isLoaded = false;
		private Windows.Modifiers modifiers;
		private Keys keyCode;
		private System.Windows.Forms.ContainerControl containerControl;
		#endregion

		#region Properties

		/// <summary>
		/// Gets value indicates if the object has been disposed.
		/// </summary>
		[Browsable(false)]
		public bool IsDisposed { get; private set; }

		/// <summary>
		/// Gets or sets the key modifier for the global hot key.
		/// </summary>
		[Editor(typeof(FlagsTypeEditor<Modifiers>), typeof(UITypeEditor))]
		[Description("Gets or sets the key modifier for the global hot key")]
		public Modifiers Modifiers
		{
			get { return this.modifiers; }
			set
			{
				ThrowIfDisposed();

				if (this.isLoaded)
				{
					throw new InvalidOperationException("Global hot key already set");
				}

				if (!EnumExtansions.IsCombinationDefined(value))
				{
					throw new ArgumentException();
				}

				this.modifiers = value;
			}
		}

		/// <summary>
		/// Gets or sets he key to combine with the modifiers for the global hot key
		/// </summary>
		[Description("Gets or sets he key to combine with the modifiers for the global hot key")]
		public Keys KeyCode
		{
			get { return this.keyCode; }
			set
			{
				ThrowIfDisposed();

				if (this.isLoaded)
				{
					throw new InvalidOperationException("Global hot key already set");
				}

				this.keyCode = value;
			}
		}

		/// <summary>
		/// Gets or sets the container control.
		/// </summary>
		[Browsable(false)]
		public ContainerControl ContainerControl
		{
			get { return this.containerControl; }
			set
			{
				this.containerControl = value;

				this.hWnd = value != null
					? value.Handle
					: IntPtr.Zero;
			}
		}

		/// <summary>
		/// Gets or sets the site for the component.
		/// </summary>
		[Browsable(false)]
		public override ISite Site
		{
			get { return base.Site; }
			set
			{
				base.Site = value;
				
				if (value != null)
				{

					var host = value.GetService(typeof(IDesignerHost)) as IDesignerHost;

					if (host != null)
					{
						IComponent componentHost = host.RootComponent;

						if (componentHost is ContainerControl)
						{
							ContainerControl = componentHost as ContainerControl;
						}
					}
				}
			}
		}
		#endregion

		#region Events

		/// <summary>
		/// Occurs when the global hot key is pressed by the user
		/// </summary>
		[Description("Occurs when the global hot key is pressed by the user")]
		public event EventHandler HotKeyPressed = delegate { };
		#endregion

		#region Ctors

		/// <summary>
		/// Creates new instance of the global hot key.
		/// </summary>
		public GlobalHotKey()
			: this(null) { }

		/// <summary>
		/// Creates new instance of the global hot key for the given container.
		/// </summary>
		/// <param name="container">The container which will contain the globel hot key.</param>
		public GlobalHotKey(IContainer container)
		{
			if (container != null)
			{
				container.Add(this);

				if (container is IWin32Window)
				{
					this.hWnd = (container as IWin32Window).Handle;
				}
			}
			
			InitializeComponent();
			Application.AddMessageFilter(this);
		}

		/// <summary>
		/// Creates new instance of the global hot key for the window with the given handle.
		/// </summary>
		/// <param name="hWnd">The handle of the window which will be associated with the global hot key.</param>
		public GlobalHotKey(IntPtr hWnd) : this()
		{
			this.hWnd = hWnd;
		}

		/// <summary>
		/// Creates new instance of the global hot key for the given container, and window with the given handle.
		/// </summary>
		/// <param name="container">The container which will contain the globel hot key.</param>
		/// <param name="hWnd">The handle of the window which will be associated with the global hot key.</param>
		public GlobalHotKey(IContainer container, IntPtr hWnd)
			: this(container)
		{
			this.hWnd = hWnd;
		}

		/// <summary>
		/// Finalizer for the key.
		/// </summary>
		~GlobalHotKey()
		{
			Dispose(false);
		}
		#endregion

		#region Methods

		/// <summary>
		/// Sets the global hotkey.
		/// </summary>
		public void RegisterGlobalHotKey()
		{
			ThrowIfDisposed();

			if (this.isLoaded)
			{
				throw new InvalidOperationException("Global hot key already set");
			}

			if (this.Modifiers == Windows.Modifiers.None)
			{
				throw new ArgumentException("Modifiers connot be None", "Modifiers");
			}

			this.id = GlobalAddAtom(GetType().FullName);

			if (!RegisterHotKey(this.hWnd, this.id, this.Modifiers, (uint)this.KeyCode))
			{
				throw new Win32Exception();
			}
			else
			{
				this.isLoaded = true;
			}
		}

		/// <summary>
		/// Sets the global hotkey for the given modifiers and key.
		/// </summary>
		/// <param name="modifiers">The key modifiers.</param>
		/// <param name="keyCode">The key code for the global hot key.</param>
		public void RegisterGlobalHotKey(Windows.Modifiers modifiers, Keys keyCode)
		{
			ThrowIfDisposed();

			this.Modifiers = modifiers;
			this.KeyCode = keyCode;

			RegisterGlobalHotKey();
		}

		/// <summary>
		/// Unregister the current global hot key.
		/// </summary>
		public void UnregisterGlobalHotKey()
		{
			if (!this.isLoaded)
			{
				throw new InvalidOperationException();
			}

			UnregisterHotKey(this.hWnd, this.id);
			this.isLoaded = false;
		}

		private void ThrowIfDisposed()
		{
			if (this.IsDisposed)
			{
				throw new ObjectDisposedException(string.Format(
					"GlobalHotKeys_{0}+{1}",
					this.Modifiers,
					this.KeyCode));
			}
		}

		bool IMessageFilter.PreFilterMessage(ref Message message)
		{
			bool didDispatched = false;

			if ((message.Msg == WM_HOTKEY) && (message.WParam == (IntPtr)this.id))
			{
				didDispatched = true;
				HotKeyPressed(this, EventArgs.Empty);
			}

			return didDispatched;
		}

		#region P/Invoke

		[DllImport(USER32, SetLastError = true)]
		private extern static bool RegisterHotKey(
			IntPtr hWnd, 
			int id, 
			Modifiers modifiers, 
			uint virtualKey);

		[DllImport(USER32, SetLastError = true)]
		private extern static bool UnregisterHotKey(IntPtr hWnd, int id);

		[DllImport(KERNEL32, SetLastError = true)]
		private extern static ushort GlobalAddAtom(IntPtr intAtomName);
		
		[DllImport(KERNEL32, SetLastError = true)]
		private extern static ushort GlobalAddAtom(string atomName);

		[DllImport(KERNEL32, SetLastError = true)]
		private extern static ushort GlobalDeleteAtom(ushort atom);
		#endregion
		#endregion

		
	}

	/// <summary>
	/// Key modifiers for global hot key.
	/// </summary>
	[Flags]
	public enum Modifiers : uint
	{
		/// <summary>No modifier. this value is invalid.</summary>
		None,
		/// <summary>Alt should be pressed.</summary>
		Alt = 0x0001,
		/// <summary>Alt should be pressed.</summary>
		Control = 0x0002,
		/// <summary>Shift should be pressed.</summary>
		Shift = 0x0004,
		/// <summary>Windows key should be pressed.</summary>
		WinKey = 0x0008,
		/// <summary>Long press won't produce multiple events.</summary>
		NoRepeat = 0x4000,
	}
}
