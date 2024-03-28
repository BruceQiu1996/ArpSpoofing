using System.Windows;

namespace ARPSpoofing
{
    /// <summary>
    /// Interaction logic for Detail.xaml
    /// </summary>
    public partial class Detail : Window
    {
        public Detail(DetailViewModel detailViewModel)
        {
            InitializeComponent();
            DataContext = detailViewModel;
        }
    }
}
