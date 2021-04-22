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

    # Parser for the whois.nic.xxx server.
    class WhoisNicXxx < BaseAfilias2

      self.scanner = Scanners::BaseAfilias, {
          pattern_disclaimer: /^The WHOIS information|^The data in this record|^This service is|^Uniregistry reserves/,
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


      property_supported :status do
        if reserved?
          :reserved
        else
          super()
        end
      end


      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end

    end

  end
end
