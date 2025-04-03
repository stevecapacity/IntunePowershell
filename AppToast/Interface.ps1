Add-Type -AssemblyName PresentationFramework

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="App Install Status"
        Height="400" Width="600"
        WindowStartupLocation="CenterScreen"
        Background="White"
        ResizeMode="NoResize"
        WindowStyle="SingleBorderWindow">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,10">
            <Image Source="./LOGO-BADGE.jpeg" Height="40" Width="40" Margin="0,0,10,0"/>
            <TextBlock Text="Company Name" FontSize="20" FontWeight="Bold"/> 
        </StackPanel>
        <TextBlock Grid.Row="1" Text="Welcome to your new PC.  We're finishing up the rest of your app installs.  Check back here for progress." FontSize="10" Margin="5" VerticalAlignment="Center" TextWrapping="Wrap" HorizontalAlignment="Center"/>

        <StackPanel Grid.Row="2" Orientation="Vertical" Margin="10">
            <StackPanel Orientation="Horizontal" Margin="0,5">
                <Image Source="https://www.google.com/chrome/static/images/favicons/favicon.ico" Width="24" Height="24" Margin="0,0,10,0"/>
                <TextBlock Text="Google Chrome" Width="120" VerticalAlignment="Center"/>
                <ProgressBar Width="250" Height="10" Value="90" Margin="10,0" VerticalAlignment="Center"/>
                <TextBlock Text="Installed" Width="80" Foreground="Green" VerticalAlignment="Center"/>
            </StackPanel>
        </StackPanel>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$window.ShowDialog()