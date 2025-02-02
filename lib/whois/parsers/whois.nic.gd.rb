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

    # Parser for the whois.nic.gd server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicGd < BaseAfilias2

      self.scanner = Scanners::BaseAfilias, {
        pattern_disclaimer: /^The Whois and|^Access to /,
      }

    end

  end
end
