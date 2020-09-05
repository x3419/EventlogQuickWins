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
    class Program
    {

        public static void printRelevantInfo(String inputString, String[] items)
        {
            bool found = false;
            foreach(string item in items)
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

        static void Main(string[] args)
        {

            string HostName = Dns.GetHostName();
            string csPath = @"C:\CS\";
            System.IO.Directory.CreateDirectory(csPath);
            using (StreamWriter writer = new StreamWriter(csPath + HostName + "_EventlogRDP.txt"))
            {
                Console.SetOut(writer);
                EventLog log = new EventLog("Security");
                var entries = log.Entries.Cast<EventLogEntry>()
                                         .Where(x => x.InstanceId == 4624)
                                         .Select(x => new
                                         {
                                             x.MachineName,
                                             x.Site,
                                             x.Source,
                                             x.Message
                                         }).ToList();

                foreach (var entry in entries)
                {
                    // check if its a 4624 type 10 or 7
                    if(entry.Message.Contains("Logon Type\t10") || !entry.Message.Contains("Logon Type\t7"))
                    {
                        Console.WriteLine("--------------------------------");
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
            }
            
            //Console.ReadLine();
        }
    }
}
