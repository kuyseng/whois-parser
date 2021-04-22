#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias2'


module Whois
  class Parsers

    # Parser for the whois.nic.fo server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicFo < BaseAfilias2

      self.scanner = Scanners::BaseAfilias, {
          pattern_disclaimer: /^The Whois and|^Access to/,
          pattern_reserved: /^Reserved by ICM Registry\n/,
      }

      property_supported :created_on do
        node("Creation Date") do |value|
          parse_time(value)
        end
      end

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
