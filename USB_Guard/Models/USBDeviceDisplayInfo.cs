using System;
using System.ComponentModel;

namespace USB_Guard.Models
{
    public class USBDeviceDisplayInfo : INotifyPropertyChanged
    {
        private string _name = "";
        private string _type = "";
        private string _vendorId = "";
        private string _productId = "";
        private string _status = "";
        private System.Windows.Media.Brush _statusColor = System.Windows.Media.Brushes.Gray;
        private DateTime _connectedTime = DateTime.Now;
        private bool _isAuthenticated = false;

        public string Name
        {
            get => _name;
            set { _name = value; OnPropertyChanged(nameof(Name)); }
        }

        public string Type
        {
            get => _type;
            set { _type = value; OnPropertyChanged(nameof(Type)); }
        }

        public string VendorId
        {
            get => _vendorId;
            set { _vendorId = value; OnPropertyChanged(nameof(VendorId)); }
        }

        public string ProductId
        {
            get => _productId;
            set { _productId = value; OnPropertyChanged(nameof(ProductId)); }
        }

        public string Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(nameof(Status)); }
        }

        public System.Windows.Media.Brush StatusColor
        {
            get => _statusColor;
            set { _statusColor = value; OnPropertyChanged(nameof(StatusColor)); }
        }

        public DateTime ConnectedTime
        {
            get => _connectedTime;
            set { _connectedTime = value; OnPropertyChanged(nameof(ConnectedTime)); }
        }

        public bool IsAuthenticated
        {
            get => _isAuthenticated;
            set { _isAuthenticated = value; OnPropertyChanged(nameof(IsAuthenticated)); }
        }

        public string ConnectedTimeDisplay => ConnectedTime.ToString("HH:mm:ss");
        public string AuthenticationStatus => IsAuthenticated ? "? Verified" : "? Pending";

        public event PropertyChangedEventHandler PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}