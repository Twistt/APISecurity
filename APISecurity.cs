using crypto;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace APISecurity
{    // Multiuse attribute.
    public class APISecurityMiddleware
    {

        private readonly RequestDelegate _next;
        private HttpContext _context;

        public APISecurityMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        //http://localhost:62949/api/Test/?ts=6/17/2014%2010:30:00%20AM&key=test&hash=dff26098db2ce5a9085add8a772ed67
        public async Task InvokeAsync(HttpContext context)
        {
            _context = context;
            var url = context.Request.Path.ToString();
            string hashvalue = "";
            if (url.Contains("/api/"))
            {
                Console.WriteLine($"\r\n  {DateTime.Now}");

                //get the server-side copy of the secret
                //var secret = DataCache.Keys.Where(k => k.Private == key).FirstOrDefault().Secret;
                var secret = "test";
                if (secret == null) Unauthorized("Invalid or expired key.");
                url += secret;
                url = url.Replace("&hash=" + hashvalue, "");
                string hash = GetMd5Hash(MD5.Create(), url);

                using (MD5 md5Hash = MD5.Create())
                {
                    hash = GetMd5Hash(md5Hash, url);

                    Console.WriteLine("The MD5 hash of " + url + " is: " + hash + ".");

                    //Console.WriteLine("Verifying the hash...");
                    if (!VerifyMd5Hash(md5Hash, url, hash)) Unauthorized("Hash does not match. Did you forget your secret?");

                    if (hash != hashvalue)
                    {
                        Unauthorized("Hash does not match. Did you forget your secret?");
                    }
                }

                
            }

            // Call the next delegate/middleware in the pipeline
            await _next(context);
        }
        public void Unauthorized(string text)
        {
            _context.Response.StatusCode = 403;
            _context.Response.WriteAsync(text);
        }
          
        public static string GetMd5Hash(MD5 md5Hash, string input)
        {

            // Convert the input string to a byte array and compute the hash. 
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes 
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data  
            // and format each one as a hexadecimal string. 
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string. 
            return sBuilder.ToString();
        }

        // Verify a hash against a string. 
        public static bool VerifyMd5Hash(MD5 md5Hash, string input, string hash)
        {
            // Hash the input. 
            string hashOfInput = GetMd5Hash(md5Hash, input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
    public class Security
    {
       
    }
}
