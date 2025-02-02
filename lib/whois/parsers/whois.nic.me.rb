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

    # Parser for the whois.nic.me server.
    class WhoisNicMe < BaseAfilias

      self.scanner = Scanners::BaseAfilias, {
        # Disclaimer starts with "Access to" in .me servers
        pattern_disclaimer: /^Access to/
      }

      property_supported :status do
        Array.wrap(node("Domain Status"))
      end


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


      property_supported :nameservers do
        Array.wrap(node("Name Server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end


      private

      def build_contact(element, type)
        node("#{element} ID") do
          address = ["", "2", "3"].
              map { |i| node("#{element} Address#{i}") }.
              delete_if(&:empty?).
              join("\n")

          Parser::Contact.new(
            type:         type,
            id:           node("#{element} ID"),
            name:         node("#{element} Name"),
            organization: node("#{element} Organization"),
            address:      address,
            city:         node("#{element} City"),
            zip:          node("#{element} Postal Code"),
            state:        node("#{element} State/Province"),
            country_code: node("#{element} Country/Economy"),
            phone:        node("#{element} Phone"),
            fax:          node("#{element} FAX"),
            email:        node("#{element} E-mail")
          )
        end
      end

      def decompose_registrar(value)
        if value =~ /^(.+?) ([^\s]+)$/
          [$2, $1]
        end
      end

    end

  end
end
