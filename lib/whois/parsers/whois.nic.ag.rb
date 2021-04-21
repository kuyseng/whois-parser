#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.nic.ag server.
    class WhoisNicAg < BaseAfilias
      self.scanner = Scanners::BaseAfilias, {
        pattern_disclaimer: /^Access to/
      }

      property_supported :updated_on do
        node("Updated Date") do |value|
          parse_time(value)
        end
      end

      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end
    end

  end
end
