// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Cocoa

private let fontSize: CGFloat = 15

class ConfTextStorage: NSTextStorage {
    let defaultFont = NSFontManager.shared.convertWeight(true, of: NSFont.systemFont(ofSize: fontSize))
    private let boldFont = NSFont.boldSystemFont(ofSize: fontSize)
    private lazy var italicFont = NSFontManager.shared.convert(defaultFont, toHaveTrait: .italicFontMask)

    private var textColorTheme: ConfTextColorTheme.Type?

    private let backingStore: NSMutableAttributedString
    private(set) var hasError = false
    private(set) var privateKeyString: String?

    private(set) var hasOnePeer: Bool = false
    private(set) var lastOnePeerAllowedIPs: [IPAddressRange] = []
    private(set) var lastOnePeerDNSServers: [DNSServer] = []

    override init() {
        backingStore = NSMutableAttributedString(string: "")
        super.init()
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    required init?(pasteboardPropertyList propertyList: Any, ofType type: NSPasteboard.PasteboardType) {
        fatalError("init(pasteboardPropertyList:ofType:) has not been implemented")
    }

    func nonColorAttributes(for highlightType: highlight_type) -> [NSAttributedString.Key: Any] {
        switch highlightType.rawValue {
        case HighlightSection.rawValue, HighlightField.rawValue:
            return [.font: boldFont]
        case HighlightPublicKey.rawValue, HighlightPrivateKey.rawValue, HighlightPresharedKey.rawValue,
             HighlightIP.rawValue, HighlightCidr.rawValue, HighlightHost.rawValue, HighlightPort.rawValue,
             HighlightMTU.rawValue, HighlightKeepalive.rawValue, HighlightDelimiter.rawValue:
            return [.font: defaultFont]
        case HighlightComment.rawValue:
            return [.font: italicFont]
        case HighlightError.rawValue:
            return [.font: defaultFont, .underlineStyle: 1]
        default:
            return [:]
        }
    }

    func updateAttributes(for textColorTheme: ConfTextColorTheme.Type) {
        self.textColorTheme = textColorTheme
        highlightSyntax()
    }

    override var string: String {
        return backingStore.string
    }

    override func attributes(at location: Int, effectiveRange range: NSRangePointer?) -> [NSAttributedString.Key: Any] {
        return backingStore.attributes(at: location, effectiveRange: range)
    }

    override func replaceCharacters(in range: NSRange, with str: String) {
        beginEditing()
        backingStore.replaceCharacters(in: range, with: str)
        edited(.editedCharacters, range: range, changeInLength: str.count - range.length)
        endEditing()
    }

    override func replaceCharacters(in range: NSRange, with attrString: NSAttributedString) {
        beginEditing()
        backingStore.replaceCharacters(in: range, with: attrString)
        edited(.editedCharacters, range: range, changeInLength: attrString.length - range.length)
        endEditing()
    }

    override func setAttributes(_ attrs: [NSAttributedString.Key: Any]?, range: NSRange) {
        beginEditing()
        backingStore.setAttributes(attrs, range: range)
        edited(.editedAttributes, range: range, changeInLength: 0)
        endEditing()
    }

    func resetLastPeer() {
        hasOnePeer = false
        lastOnePeerAllowedIPs = []
        lastOnePeerDNSServers = []
    }

    func evaluateExcludePrivateIPs(highlightSpans: UnsafePointer<highlight_span>) {
        var spans = highlightSpans
        var fieldType = 0
        resetLastPeer()
        while spans.pointee.type != HighlightEnd {
            let span = spans.pointee
            var substring = backingStore.attributedSubstring(from: NSRange(location: span.start, length: span.len)).string

            if span.type == HighlightError {
                resetLastPeer()
                return
            }
            if span.type == HighlightSection {
                if substring.lowercased() == "[peer]" {
                    if hasOnePeer {
                        resetLastPeer()
                        return
                    }
                    hasOnePeer = true
                }
            } else if span.type == HighlightField {
                let field = substring.lowercased()
                if field == "dns" {
                    fieldType = 1
                } else if field == "allowedips" {
                    fieldType = 2
                } else {
                    fieldType = 0
                }
            } else if span.type == HighlightIP && fieldType == 1 {
                if let parsed = DNSServer(from: substring) {
                    lastOnePeerDNSServers.append(parsed)
                }
            } else if span.type == HighlightIP && fieldType == 2 {
                let next = spans.successor()
                let nextnext = next.successor()
                if next.pointee.type == HighlightDelimiter && nextnext.pointee.type == HighlightCidr {
                    substring += backingStore.attributedSubstring(from: NSRange(location: next.pointee.start, length: next.pointee.len)).string +
                                 backingStore.attributedSubstring(from: NSRange(location: nextnext.pointee.start, length: nextnext.pointee.len)).string
                }
                if let parsed = IPAddressRange(from: substring) {
                    lastOnePeerAllowedIPs.append(parsed)
                }
            }
            spans = spans.successor()
        }
    }

    func highlightSyntax() {
        guard let textColorTheme = textColorTheme else { return }
        hasError = false
        privateKeyString = nil

        let fullTextRange = NSRange(location: 0, length: (backingStore.string as NSString).length)

        backingStore.beginEditing()
        let defaultAttributes: [NSAttributedString.Key: Any] = [
            .foregroundColor: textColorTheme.defaultColor,
            .font: defaultFont
        ]
        backingStore.setAttributes(defaultAttributes, range: fullTextRange)
        var spans = highlight_config(backingStore.string.cString(using: String.Encoding.utf8))!
        evaluateExcludePrivateIPs(highlightSpans: spans)

        while spans.pointee.type != HighlightEnd {
            let span = spans.pointee

            let range = NSRange(location: span.start, length: span.len)
            backingStore.setAttributes(nonColorAttributes(for: span.type), range: range)
            let color = textColorTheme.colorMap[span.type.rawValue, default: textColorTheme.defaultColor]
            backingStore.addAttribute(.foregroundColor, value: color, range: range)

            if span.type == HighlightError {
                hasError = true
            }

            if span.type == HighlightPrivateKey {
                privateKeyString = backingStore.attributedSubstring(from: NSRange(location: span.start, length: span.len)).string
            }

            spans = spans.successor()
        }
        backingStore.endEditing()

        beginEditing()
        edited(.editedAttributes, range: fullTextRange, changeInLength: 0)
        endEditing()
    }

}
