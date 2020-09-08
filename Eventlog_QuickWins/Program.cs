using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Eventlog_QuickWins
{
    public class Program
    {

        public static void printRelevantInfo(String inputString, String[] items)
        {
            bool found = false;
            foreach (string item in items)
            {
                if (inputString.Contains(item))
                {
                    found = true;
                    break;
                }
            }
            if (found && !inputString.EndsWith("-")) // It's a thing we want to print and it's not empty (-)
            {
                Console.WriteLine(inputString);
            }
        }

        public static void Main()
        {

            string HostName = Dns.GetHostName();
            string csPath = @"C:\CS\";
            System.IO.Directory.CreateDirectory(csPath);
            using (StreamWriter writer = new StreamWriter(csPath + HostName + "_EventlogRDP.txt"))
            {
                Console.SetOut(writer);

                // First check the security eventlog for RDPs
                EventLog log = new EventLog("Security");
                var entries = log.Entries.Cast<EventLogEntry>()
                                         .Where(x => x.InstanceId == 4624)
                                         .Select(x => new
                                         {
                                             x.MachineName,
                                             x.Site,
                                             x.Source,
                                             x.Message,
                                             x.TimeGenerated,
                                         }).ToList();

                foreach (var entry in entries)
                {
                    // check if its a 4624 type 10 or 7
                    if (entry.Message.Contains("Logon Type\t10") || !entry.Message.Contains("Logon Type\t7"))
                    {
                        Console.WriteLine("--------------------------------");
                        Console.WriteLine(entry.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
                        Console.WriteLine("EventID: 4624");
                        string[] wordsToMatch = { "Logon Type", "Workstation Name", "Source Network Address", "Network Account Name", "Account Name", "Account Domain" };

                        using (StringReader reader = new StringReader(entry.Message))
                        {
                            string line = string.Empty;
                            do
                            {
                                line = reader.ReadLine();
                                if (line != null)
                                {
                                    printRelevantInfo(line, wordsToMatch);
                                }

                            } while (line != null);
                        }
                        Console.WriteLine("--------------------------------");
                    }

                }

                // Then check Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx for logons
                using (var reader = new EventLogReader(@"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", PathType.FilePath))
                {
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            if (record.Id == 21 || record.Id == 23 || record.Id == 24)
                            {
                                Console.WriteLine("--------------------------------");
                                Console.WriteLine(DateTime.Parse(record.TimeCreated.ToString()).ToString("yyyy-MM-ddTHH:mm:ssZ"));
                                Console.WriteLine("EventID: " + record.Id);
                                Console.WriteLine(record.FormatDescription());
                                Console.WriteLine("--------------------------------");
                            }


                        }
                    }
                }

            }

            // Powershell


            using (StreamWriter writer = new StreamWriter(csPath + HostName + "_EventlogPowershell.txt"))
            {
                Console.SetOut(writer);

                // Powershell operational
                using (var reader = new EventLogReader(@"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx", PathType.FilePath))
                {
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            if (record.Id == 4104)
                            {
                                Console.WriteLine("--------------------------------");
                                Console.WriteLine(DateTime.Parse(record.TimeCreated.ToString()).ToString("yyyy-MM-ddTHH:mm:ssZ"));
                                Console.WriteLine("EventID: " + record.Id);
                                Console.WriteLine(record.FormatDescription());
                                Console.WriteLine("--------------------------------");
                            }


                        }
                    }
                }


                // Microsoft-Windows-PowerShell
                EventLog log = new EventLog("Windows PowerShell");
                var entries = log.Entries.Cast<EventLogEntry>()
                                         //.Where(x => x.InstanceId == 600)
                                         .Select(x => new
                                         {
                                             x.MachineName,
                                             x.Site,
                                             x.Source,
                                             x.Message,
                                             x.TimeGenerated,
                                             x.InstanceId,
                                         }).ToList();

                foreach (var entry in entries)
                {


                    bool shouldPrint = false;
                    using (StringReader reader = new StringReader(entry.Message))
                    {
                        string line = string.Empty;
                        do
                        {
                            line = reader.ReadLine();
                            if (line != null)
                            {
                                if (line.Contains("HostApplication") && !line.EndsWith("powershell.exe") || (line.Contains("ScriptName=") && !line.EndsWith("ScriptName=")) || (line.Contains("CommandLine=") && !line.EndsWith("CommandLine="))) // if there's something non-default
                                {
                                    shouldPrint = true;
                                }

                            }

                        } while (line != null);
                    }

                    if (shouldPrint)
                    {
                        Console.WriteLine("--------------------------------");
                        Console.WriteLine(entry.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
                        Console.WriteLine("EventID: " + entry.InstanceId);

                        using (StringReader reader = new StringReader(entry.Message))
                        {
                            string line = string.Empty;
                            do
                            {
                                line = reader.ReadLine();
                                if (line != null)
                                {
                                    if (line.Contains("HostApplication") && !line.EndsWith("powershell.exe") || (line.Contains("ScriptName=") && !line.EndsWith("ScriptName=")) || (line.Contains("CommandLine=") && !line.EndsWith("CommandLine="))) // if there's something non-default
                                    {
                                        Console.WriteLine(line.Replace("\t", ""));
                                    }
                                }

                            } while (line != null);
                        }

                        Console.WriteLine("--------------------------------");
                    }



                }
            }



        }
    }
}