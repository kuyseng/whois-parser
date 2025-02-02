# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.club/club/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.nic.club.rb'

describe Whois::Parsers::WhoisNicClub, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.nic.club/club/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#domain" do
    it do
      expect(subject.domain).to eq("nic.club")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("D313-CLUB")
    end
  end
  describe "#status" do
    it do
      expect(subject.status).to eq(:registered)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(true)
    end
  end
  describe "#created_on" do
    it do
      expect(subject.created_on).to be_a(Time)
      expect(subject.created_on).to eq(Time.parse("2013-08-09 23:33:53 UTC"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2017-07-14 08:48:42 UTC"))
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to be_a(Time)
      expect(subject.expires_on).to eq(Time.parse("2024-08-08 23:59:59 UTC"))
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq("C312-CLUB")
      expect(subject.registrant_contacts[0].name).to eq("Domain Administrator")
      expect(subject.registrant_contacts[0].organization).to eq(".CLUB Domains, LLC")
      expect(subject.registrant_contacts[0].address).to eq("100 S.E. 3rd Ave.,, Suite 1310")
      expect(subject.registrant_contacts[0].city).to eq("Fort Lauderdale")
      expect(subject.registrant_contacts[0].zip).to eq("33394-0054")
      expect(subject.registrant_contacts[0].state).to eq("FL")
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq("US")
      expect(subject.registrant_contacts[0].phone).to eq("+1.8778330000")
      expect(subject.registrant_contacts[0].fax).to eq("")
      expect(subject.registrant_contacts[0].email).to eq("domainadmin@nic.club")
      expect(subject.registrant_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].id).to eq("C312-CLUB")
      expect(subject.admin_contacts[0].name).to eq("Domain Administrator")
      expect(subject.admin_contacts[0].organization).to eq(".CLUB Domains, LLC")
      expect(subject.admin_contacts[0].address).to eq("100 S.E. 3rd Ave.,, Suite 1310")
      expect(subject.admin_contacts[0].city).to eq("Fort Lauderdale")
      expect(subject.admin_contacts[0].zip).to eq("33394-0054")
      expect(subject.admin_contacts[0].state).to eq("FL")
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq("US")
      expect(subject.admin_contacts[0].phone).to eq("+1.8778330000")
      expect(subject.admin_contacts[0].fax).to eq("")
      expect(subject.admin_contacts[0].email).to eq("domainadmin@nic.club")
      expect(subject.admin_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#technical_contacts" do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts.size).to eq(1)
      expect(subject.technical_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.technical_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_TECHNICAL)
      expect(subject.technical_contacts[0].id).to eq("C312-CLUB")
      expect(subject.technical_contacts[0].name).to eq("Domain Administrator")
      expect(subject.technical_contacts[0].organization).to eq(".CLUB Domains, LLC")
      expect(subject.technical_contacts[0].address).to eq("100 S.E. 3rd Ave.,, Suite 1310")
      expect(subject.technical_contacts[0].city).to eq("Fort Lauderdale")
      expect(subject.technical_contacts[0].zip).to eq("33394-0054")
      expect(subject.technical_contacts[0].state).to eq("FL")
      expect(subject.technical_contacts[0].country).to eq(nil)
      expect(subject.technical_contacts[0].country_code).to eq("US")
      expect(subject.technical_contacts[0].phone).to eq("+1.8778330000")
      expect(subject.technical_contacts[0].fax).to eq("")
      expect(subject.technical_contacts[0].email).to eq("domainadmin@nic.club")
      expect(subject.technical_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(6)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("ns4.dns.nic.club")
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns1.dns.nic.club")
      expect(subject.nameservers[2]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[2].name).to eq("ns3.dns.nic.club")
      expect(subject.nameservers[3]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[3].name).to eq("ns2.dns.nic.club")
      expect(subject.nameservers[4]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[4].name).to eq("ns6.dns.nic.club")
      expect(subject.nameservers[5]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[5].name).to eq("ns5.dns.nic.club")
    end
  end
end
