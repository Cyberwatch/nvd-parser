puts "\
┌────────────────────────────────────────────────────────────────────┐
│ Vulnerabilities statistics v0.1.1                                  │
├────────────────────────────────────────────────────────────────────┤
│ Copyright © 2014 Maxime Alay-Eddine @tarraschk                     │
│ Copyright © 2014 ARGAUS SAS Cybersecurity (http://www.argaus.fr)   │
├────────────────────────────────────────────────────────────────────┤
│ Licensed under the MIT license.                                    │
├────────────────────────────────────────────────────────────────────┤
│ This script has been made to compute the number of                 |
| vulnerabilities in Information Systems, based on the US-NVD data.  |
└────────────────────────────────────────────────────────────────────┘
"

# -- License

'''
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''

# -- Dependencies
require 'trollop'
require 'json'
require 'nokogiri'
require 'set'

# -- Parsing commands with CLI
opts = Trollop::options do
  version "Vulstats 0.1.1 (c) 2014 Maxime Alay-Eddine, ARGAUS SAS"
  banner <<-EOS
Vulstats parses NVD data XML to build a JSON that you can plot.

Usage:
       vulstats [options] -f filename
where [options] are:
EOS

  opt :verbose, "Verbose mode"
  opt :file, "NVD XML file to parse", :type => String
end
Trollop::die :file, "must exist" unless File.exist?(opts[:file]) if opts[:file]

if opts[:file].nil? || opts[:file].empty?
  abort "Error: please specify an existing file. \n    Example: Vulstats.rb -f nvdcve-2.0-2012.xml"
end


# -- Preparing statistics variables
results = Hash.new
results["count_vulnerabilities"] = 0
results["count_vendors"] = 0
results["vendors"] = Array.new

# -- Loading file
start = Time.now
puts "Importing file..."
f = File.open(opts[:file])
@doc = Nokogiri::XML(f)
f.close
puts "File imported!"
verif = 0
puts "Parsing..."
@doc.xpath("//xmlns:entry").each do |entry| # For each Vulnerability in the Dataset
  puts "# ENTRY found: "+entry['id'] unless !opts[:verbose]
  results["count_vulnerabilities"] = results["count_vulnerabilities"] + 1 # Increments the number of Vulnerabilities
  # -- Fetching CVSS score
  cvss_score = entry.xpath("vuln:cvss//cvss:base_metrics//cvss:score").text.to_f
  # -- Fetching Products associated with the vulnerability
  product_set = Set.new
  # Here we filter the vulnerability to remove their versions
  entry.xpath("vuln:vulnerable-software-list//vuln:product").each do |product|
    product_set.add(product.text.split(":")[2]+":"+product.text.split(":")[3])
  end
  puts "## CVSS SCORE found: "+cvss_score.to_s unless !opts[:verbose]
  # Now we add them to the result Array
  puts "## PRODUCTS found:" unless !opts[:verbose]
  product_set.each do |prod|
    tech_vendor = prod.split(":")[0]
    tech_product = prod.split(":")[1]
    puts "### VENDOR found: "+tech_vendor unless !opts[:verbose]
    puts "### PRODUCT found: "+tech_product unless !opts[:verbose]
    if vendor = results["vendors"].find { |v| v["vendor"] == tech_vendor }
      if product = vendor["products"].find { |p| p["product"] == tech_product }
        product["cvss_scores"].push(cvss_score)
        product["count_vulnerabilities"] = product["count_vulnerabilities"] + 1
      else
        product_new = Hash.new
        product_new["product"] = tech_product
        product_new["count_vulnerabilities"] = 1
        product_new["cvss_scores"] = [cvss_score]
        vendor["products"].push(product_new)
        vendor["count_products"] = vendor["count_products"] + 1
      end
    else
      vendor_new = Hash.new
      vendor_new["vendor"] = tech_vendor
      vendor_new["count_products"] = 1
      vendor_new["products"] = Array.new
      product_new = Hash.new
      product_new["product"] = tech_product
      product_new["count_vulnerabilities"] = 1
      product_new["cvss_scores"] = [cvss_score]
      vendor_new["products"].push(product_new)
      results["vendors"].push(vendor_new)
      results["count_vendors"] = results["count_vendors"] + 1
    end
    #puts tech_vendor
    #puts tech_product

    #if results[tech_vendor].nil?
    #  results[tech_vendor] = Array.new
    #end
    #if results[tech_vendor][tech_product].nil?
    #  results[tech_vendor][tech_product] =
    #results[tech_vendor].push(entry.xpath("vuln:cvss//cvss:base_metrics//cvss:score").text.to_f)
  end
end
puts "Parsed!" unless !opts[:verbose]
puts "Done!..." unless !opts[:verbose]
finish = Time.now
diff = finish - start
puts "Executed in "+diff.to_s+" seconds."
puts results.to_json unless !opts[:verbose]

begin
  output_filename = "results_"+opts[:file].split("/").last+".json"
  puts "Exporting to "+output_filename+"..."
  fileResult = File.open(output_filename, "w")
  fileResult.write(results.to_json)
  puts "Done! Exiting..."
rescue IOError => e
  #some error
ensure
  fileResult.close unless fileResult == nil
end
