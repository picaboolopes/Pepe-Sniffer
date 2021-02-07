using System;
using System.Drawing;
using System.Windows.Forms;
using System.Net.Sockets;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PepeSniffer
{
    public partial class Sniffer : Form
    {
        public Sniffer()
        {
            InitializeComponent();
        }

        private BindingSource bindingSource = new BindingSource();
        private NetworkInterface[] networkInterfaces;
        private Monitor currentMonitor;
        private List<Monitor> monitorList = new List<Monitor>();
        private List<Packet> packetsList = new List<Packet>();
        private string protocolFilter = "ALL";

        private delegate void refresh(Packet p);

        private void Sniffer_Load(object sender, EventArgs e)
        {
            DGV.AutoGenerateColumns = false;
            DGV.DataSource = bindingSource;
            DGV.Columns["SourceIp"].DataPropertyName = "SourceIp";
            DGV.Columns["SourcePort"].DataPropertyName = "SourcePort";
            DGV.Columns["DestinationIp"].DataPropertyName = "DestinationIP";
            DGV.Columns["DestinationPort"].DataPropertyName = "DestinationPort";
            DGV.Columns["Protocol"].DataPropertyName = "Protocol";
            DGV.Columns["Time"].DataPropertyName = "Time";
            DGV.Columns["Length"].DataPropertyName = "TotalLength";
            DGV.Columns["Data"].DataPropertyName = "CharString";

            networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            for (var i = 0; i <= networkInterfaces.Length - 1; i++)
                cbInterfaces.Items.Add(networkInterfaces[i].Name);

            cbInterfaces.SelectedIndex = 0;
            cbProtocol.SelectedIndex = 0;
        }

        private bool StartReceiving()
        {
            if (cbInterfaces.SelectedIndex == 0) // All interfaces
            {
                monitorList.Clear();
                IPAddress[] hosts = Dns.GetHostEntry(Dns.GetHostName()).AddressList;

                for (int i = 0; i < hosts.Length; i++)
                {
                    Monitor monitor = new Monitor(hosts[i]);
                    monitor.PacketEventHandler += new Monitor.NewPacketEventHandler(OnNewPacket);
                    monitorList.Add(monitor);
                }

                foreach (Monitor monitor in monitorList)
                {
                    monitor.Start();
                }
                return true;
            }
            else
            {
                int index = cbInterfaces.SelectedIndex - 1;

                IPAddress myIp = null;
                IPInterfaceProperties interfaceProperties = networkInterfaces[index].GetIPProperties();

                for (int i = 0; i <= interfaceProperties.UnicastAddresses.Count - 1; i++)
                {
                    if (interfaceProperties.UnicastAddresses[i].Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        myIp = interfaceProperties.UnicastAddresses[i].Address;
                    }
                }

                try
                {
                    currentMonitor = new Monitor(myIp);
                    currentMonitor.PacketEventHandler += new Monitor.NewPacketEventHandler(OnNewPacket);
                    currentMonitor.Start();
                    return true;
                }
                catch (Exception)
                {
                    MessageBox.Show("Cannot listen on " + networkInterfaces[index].Name, "Connection error", default, MessageBoxIcon.Error);
                    return false;
                }
            }
            
        }

        private void StopReceiving()
        {
            if (cbInterfaces.SelectedIndex == 0) // All interfaces
            {
                foreach (Monitor monitor in monitorList)
                {
                    monitor.Stop();
                }
            }
            else
            {
                currentMonitor.Stop();
            }
                
        }

        private void OnNewPacket(Monitor monitor, Packet p) => Invoke(new refresh(OnRefresh), p);
        
        private void OnRefresh(Packet p)
        {
            packetsList.Add(p);
            AddToBindingSource(p);
            ColorRows();
            DGV.Refresh();

            if (DGV.Rows.Count != 0 && btnAutomaticScroll.Checked)
            {
                DGV.FirstDisplayedScrollingRowIndex = DGV.RowCount - 1;
            } 
                
        }

        private void AddToBindingSource(Packet p)
        {
            string showOnlyIp = tbIpFilter.Text;
            string port = tbPortFilter.Text;

            bool CheckProtocol()
            {
                if (!protocolFilter.Equals("ALL"))
                {
                    return p.Protocol.Equals(protocolFilter);
                }
                else
                {
                    return true;
                }
            }

            bool CheckIP()
            {
                if (!showOnlyIp.Equals(""))
                {
                    return p.SourceIp.StartsWith(showOnlyIp) || p.DestinationIP.StartsWith(showOnlyIp);
                }
                else
                {
                    return true;
                }
            }

            bool CheckPort()
            {
                if (!port.Equals(""))
                {
                    return p.SourcePort.Equals(port) || p.DestinationPort.Equals(port);
                }
                else
                {
                    return true;
                }
            }

            if (CheckProtocol() && CheckIP() && CheckPort())
            {
                bindingSource.Add(p);
            }
        }

        private void FilterDGV()
        {
            string showOnlyIp = tbIpFilter.Text;
            string port = tbPortFilter.Text;

            List<Packet> filteredPacketList = new List<Packet>(packetsList);

            filteredPacketList = filteredPacketList.FindAll(packet =>
                protocolFilter.Equals("ALL") || packet.Protocol.Equals(protocolFilter)
            );

            filteredPacketList = filteredPacketList.FindAll(packet =>
                showOnlyIp.Equals("") || (packet.SourceIp.StartsWith(showOnlyIp) || packet.DestinationIP.StartsWith(showOnlyIp))
            );

            filteredPacketList = filteredPacketList.FindAll(packet =>
                port.Equals("") || (packet.SourcePort.Equals(port) || packet.DestinationPort.Equals(port))
            );

            bindingSource.List.Clear();
            filteredPacketList.ForEach(p => bindingSource.Add(p));
            DGV.Refresh();
            ColorRows();
        }

        private void ColorRows()
        {
            if (btnPacketColoring.Checked)
            {
                foreach (DataGridViewRow row in DGV.Rows)
                {
                    string protocol = Convert.ToString(row.Cells["Protocol"].Value);

                    switch (protocol)
                    {
                        case "TCP":
                            row.DefaultCellStyle.BackColor = Color.Lavender;
                            break;
                        case "UDP":
                            row.DefaultCellStyle.BackColor = Color.LightCyan;
                            break;
                        case "GGP":
                            row.DefaultCellStyle.BackColor = Color.Aquamarine;
                            break;
                        case "ICMP":
                            row.DefaultCellStyle.BackColor = Color.Bisque;
                            break;
                        case "IDP":
                            row.DefaultCellStyle.BackColor = Color.LightPink;
                            break;
                        case "IGMP":
                            row.DefaultCellStyle.BackColor = Color.PaleGreen;
                            break;
                        case "IP":
                            row.DefaultCellStyle.BackColor = Color.LightYellow;
                            break;
                        case "ND":
                            row.DefaultCellStyle.BackColor = Color.Thistle;
                            break;
                        case "PUP":
                            row.DefaultCellStyle.BackColor = Color.BlanchedAlmond;
                            break;
                        case "OTHERS":
                            row.DefaultCellStyle.BackColor = Color.WhiteSmoke;
                            break;
                    }
                }
            }
            else
            {
                foreach (DataGridViewRow row in DGV.Rows)
                {
                    row.DefaultCellStyle.BackColor = Color.White;
                }
            }
        }

        private void SetSelectedRow(int index)
        {
            if (index >= 0 && index < DGV.RowCount)
            {
                DGV.CurrentCell = DGV.Rows[index].Cells[0];
                DGV_CellClick(this, new DataGridViewCellEventArgs(0, index));
            }
        }

        private void ExportPacketsAsText()
        {
            if (DGV.RowCount > 0)
            {
                SaveFileDialog sfd = new SaveFileDialog
                {
                    Filter = "Text Files(*.txt)|*.txt",
                    Title = "Export selected packets as text",
                    FileName = "packets.txt"
                };
                DialogResult dialogResult = sfd.ShowDialog();

                if (sfd.FileName != "" && dialogResult == DialogResult.OK)
                {
                    using (StreamWriter sw = new StreamWriter(sfd.OpenFile()))
                    {
                        sw.WriteLine("------------------------------------------------------------------------------------------\n");

                        foreach (Packet packet in bindingSource.List)
                        {
                            sw.WriteLine(string.Format("{0, -20}{1}", "PROTOCOL:", packet.Protocol));
                            sw.WriteLine(!string.IsNullOrEmpty(packet.SourceIp) ?
                                string.Format("{0, -20}{1}", "SOURCE:", packet.SourceIp + ":" + packet.SourcePort) :
                                string.Format("{0, -20}{1}", "SOURCE:", packet.SourceIp));
                            sw.WriteLine(!string.IsNullOrEmpty(packet.DestinationPort) ?
                                string.Format("{0, -20}{1}", "DESTINATION:", packet.DestinationIP + ":" + packet.DestinationPort) :
                                string.Format("{0, -20}{1}", "DESTINATION:", packet.DestinationIP));
                            sw.WriteLine(string.Format("{0, -20}{1} bytes", "TOTAL LENGTH:", packet.TotalLength));
                            sw.WriteLine(string.Format("{0, -20}{1}", "CAPTURE TIME:", packet.Time));
                            sw.WriteLine("\nHEX DATA:");
                            sw.WriteLine(packet.HexString.Length > 0 ?
                                packet.HexString :
                                "Empty\n");
                            sw.WriteLine("------------------------------------------------------------------------------------------\n");
                        }

                        sw.Flush();
                        sw.Close();
                    }
                }
            }
            else
            {
                MessageBox.Show("No packets to export", "Export packets as text", default, MessageBoxIcon.Warning);
            }
        }

        private void ExportSelectedPacketAsBinary()
        {
            if (DGV.SelectedRows.Count == 1)
            {
                SaveFileDialog sfd = new SaveFileDialog
                {
                    Filter = "Binary Files(*.bin)|*.bin",
                    Title = "Export packet bytes",
                    FileName = "packet_data.bin"
                };
                DialogResult dialogResult = sfd.ShowDialog();

                if (sfd.FileName != "" && dialogResult == DialogResult.OK)
                {
                    using (StreamWriter sw = new StreamWriter(sfd.OpenFile()))
                    {
                        Packet packet = (Packet)bindingSource.List[DGV.CurrentCell.RowIndex];

                        foreach (byte b in packet.Bytes)
                            sw.Write((char)b);

                        sw.Flush();
                        sw.Close();
                    }
                }
            } 
            else
            {
                MessageBox.Show("Select one packet", "Export packet bytes", default, MessageBoxIcon.Warning);
            }
        }

        private void ExportPacketsAsCsv()
        {
            if (DGV.RowCount > 0)
            {
                SaveFileDialog sfd = new SaveFileDialog
                {
                    Filter = "CSV Files(*.csv)|*.csv",
                    Title = "Export packets as CSV",
                    FileName = "packets.csv"
                };

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    int columnCount = DGV.Columns.Count;
                    string columnNames = "";
                    string[] outputCsv = new string[DGV.Rows.Count + 1];
                    for (int i = 0; i < columnCount; i++)
                    {
                        columnNames += DGV.Columns[i].HeaderText.ToString() + ",";
                    }
                    outputCsv[0] += columnNames;

                    for (int i = 1; (i - 1) < DGV.Rows.Count; i++)
                    {
                        for (int j = 0; j < columnCount; j++)
                        {
                            if (j != 7)
                            {
                                outputCsv[i] += DGV.Rows[i - 1].Cells[j].Value.ToString() + ",";
                            }
                            else // Data column
                            {
                                outputCsv[i] += '"' + DGV.Rows[i - 1].Cells[j].Value.ToString().Replace("\n", "") + '"' + ",";
                            }
                        }
                    }

                    File.WriteAllLines(sfd.FileName, outputCsv, Encoding.UTF8);
                }
            } 
            else
            {
                MessageBox.Show("No packets to export", "Export packets as CSV", default, MessageBoxIcon.Warning);
            }
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (StartReceiving())
            {
                btnStart.Enabled = false;
                btnStop.Enabled = true;
                btnExportToText.Enabled = false;
                btnExportToCsv.Enabled = false;
                btnExportBytesFromSelected.Enabled = false;
                cbInterfaces.Enabled = false;
            }
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            StopReceiving();
            btnStart.Enabled = true;
            btnStop.Enabled = false;
            btnExportToText.Enabled = true;
            btnExportToCsv.Enabled = true;
            btnExportBytesFromSelected.Enabled = true;
            cbInterfaces.Enabled = true;
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            bindingSource.Clear();
            packetsList.Clear();
            bindingSource.ResetBindings(true);
            rtbHexadecimal.Text = "";
            rtbChars.Text = "";
        }

        private void DGV_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0)
            {
                Packet p = (Packet) bindingSource.List[e.RowIndex];
                rtbHexadecimal.Text = p.HexString;
                rtbChars.Text = p.CharString;
            }
        }

        private void rtbChars_SelectionChanged(object sender, EventArgs e)
        {
            string dataText = rtbChars.Text;
            string selectedText = rtbChars.SelectedText;
            int selectedLength = selectedText.Length;

            int start0 = rtbChars.SelectionStart - selectedLength;
            int start1 = rtbChars.SelectionStart;

            int index = start0 > -1 && dataText.Substring(start0, selectedLength).Equals(selectedText) ? start0 : start1;
            string tmpString = rtbChars.Text.Substring(0, index);
            int spaceCount = getCharCount(tmpString, '\n');

            int start = tmpString.Length * 3 - 2 * spaceCount;
            int selectedHexLength = rtbChars.SelectedText.Length * 3 - 2 * getCharCount(rtbChars.SelectedText, '\n');
            if (selectedHexLength > 0)
            {
                rtbHexadecimal.SelectionStart = 0;
                rtbHexadecimal.SelectionLength = rtbHexadecimal.Text.Length;
                rtbHexadecimal.SelectionBackColor = Color.White;

                rtbHexadecimal.SelectionStart = start;
                rtbHexadecimal.SelectionLength = selectedHexLength;
                rtbHexadecimal.SelectionBackColor = Color.DodgerBlue;
            }
            else
            {
                rtbHexadecimal.SelectionBackColor = Color.White;
            }

            int getCharCount(string s, char c)
            {
                int count = 0;
                for (int i = 0; i < s.Length; i++)
                {
                    if (s[i] == c)
                        count++;
                }
                return count;
            }
        }

        private void rtbChars_Leave(object sender, EventArgs e)
        {
            rtbHexadecimal.SelectionBackColor = Color.White;
        }

        private void cbProtocol_SelectionChangeCommitted(object sender, EventArgs e)
        {
            protocolFilter = cbProtocol.SelectedItem.ToString();
            FilterDGV();
        }

        private void tbPortFilter_TextChanged(object sender, EventArgs e)
        {
            try
            {
                if (tbPortFilter.Text != "" & tbPortFilter.Text != null)
                {
                    int.Parse(tbPortFilter.Text);
                    tbPortFilter.BackColor = Color.LimeGreen;
                }
                else
                {
                    tbPortFilter.BackColor = Color.White;
                }
            }
            catch (Exception)
            {
                tbPortFilter.BackColor = Color.Crimson;
            }
            finally
            {
                FilterDGV();
            }
        }

        private void tbIpFilter_TextChanged(object sender, EventArgs e)
        {
            try
            {
                if (tbIpFilter.Text != "" & tbIpFilter.Text != null)
                {
                    IPAddress.Parse(tbIpFilter.Text);
                    tbIpFilter.BackColor = Color.LimeGreen;
                }
                else
                {
                    tbIpFilter.BackColor = Color.White;
                }
            }
            catch (Exception)
            {
                tbIpFilter.BackColor = Color.Crimson;
            }
            finally
            {
                FilterDGV();
            }
        }

        private void btnPrevious_Click(object sender, EventArgs e)
        {
            if (DGV.CurrentCell != null) 
                SetSelectedRow(DGV.CurrentCell.RowIndex -1);
        }

        private void btnNext_Click(object sender, EventArgs e)
        {
            if (DGV.CurrentCell != null) 
                SetSelectedRow(DGV.CurrentCell.RowIndex + 1);
        }

        private void btnFirst_Click(object sender, EventArgs e)
        {
            if (DGV.CurrentCell != null)
                SetSelectedRow(0);
        }

        private void btnLast_Click(object sender, EventArgs e)
        {
            if (DGV.CurrentCell != null)
                SetSelectedRow(DGV.RowCount - 1);
        }

        private void btnQuit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void btnPacketColoring_Click(object sender, EventArgs e)
        {
            ColorRows();
        }

        private void btnExportToText_Click(object sender, EventArgs e)
        {
            ExportPacketsAsText();
        }

        private void btnExportToCsv_Click(object sender, EventArgs e)
        {
            ExportPacketsAsCsv();
        }

        private void btnExportBytesFromSelected_Click(object sender, EventArgs e)
        {
            ExportSelectedPacketAsBinary();
        }

    }
}