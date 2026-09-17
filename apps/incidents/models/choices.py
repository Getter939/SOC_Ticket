# ── Unified source / reporting-channel vocabulary ────────────────────────── #
# "How an incident reached the SOC." Shared by Ticket.issue_type (the channel
# recorded on a ticket) and TriageRecord.source (the manual-intake channel), so
# a triage record maps 1:1 onto the ticket it spawns (see create_ticket
# auto-fill). SIEM counts as a reporting channel. Values are UPPER_SNAKE codes;
# the labels are what users see.
SOURCE_SIEM        = 'SIEM'
SOURCE_ADMIN       = 'ADMIN'
SOURCE_TI          = 'TI'
SOURCE_EMAIL       = 'EMAIL'
SOURCE_PHONE       = 'PHONE'
SOURCE_USER_REPORT = 'USER_REPORT'
SOURCE_EXTERNAL    = 'EXTERNAL'
SOURCE_OTHER       = 'OTHER'

SOURCE_CHOICES = [
    (SOURCE_SIEM,        'ระบบเฝ้าระวัง (SIEM)'),
    (SOURCE_ADMIN,       'ผู้ดูแลระบบ (Admin)'),
    (SOURCE_TI,          'Threat Intelligence (TI)'),
    (SOURCE_EMAIL,       'Email'),
    (SOURCE_PHONE,       'Phone / Hotline'),
    (SOURCE_USER_REPORT, 'User / Internal Report'),
    (SOURCE_EXTERNAL,    'หน่วยงานภายนอก (External Organization)'),
    (SOURCE_OTHER,       'Other'),
]
