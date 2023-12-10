export const OpenBadgeSchema = {
    $schema: "https://json-schema.org/draft/2019-09/schema#",
    $id: "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
    title: "JSON Schema for the AchievementCredential class.",
    description:
        "AchievementCredentials are representations of an awarded achievement, used to share information about a achievement belonging to one earner. Maps to a Verifiable Credential as defined in the [[VC-DATA-MODEL]]. As described in [[[#data-integrity]]], at least one proof mechanism, and the details necessary to evaluate that proof, MUST be expressed for a credential to be a verifiable credential. In the case of an embedded proof, the credential MUST append the proof in the `proof` property.",
    type: "object",
    properties: {
        "@context": {
            type: "array",
            minItems: 1,
            items: {
                $ref: "#/$defs/Context",
            },
        },
        id: {
            description: "Unambiguous reference to the credential.",
            $comment:
                "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
            type: "string",
        },
        type: {
            oneOf: [
                {
                    description:
                        "The value of the type property MUST be an unordered set. One of the items MUST be the URI 'VerifiableCredential', and one of the items MUST be the URI 'AchievementCredential' or the URI 'OpenBadgeCredential'.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
                {
                    type: "array",
                    minItems: 1,
                    items: {
                        description:
                            "The value of the type property MUST be an unordered set. One of the items MUST be the URI 'VerifiableCredential', and one of the items MUST be the URI 'AchievementCredential' or the URI 'OpenBadgeCredential'.",
                        $comment:
                            "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                        type: "string",
                    },
                },
            ],
        },
        name: {
            description:
                "The name of the credential for display purposes in wallets. For example, in a list of credentials and in detail views.",
            $comment: "Origin: String (PrimitiveType); Character strings.",
            type: "string",
        },
        description: {
            description:
                "The short description of the credential for display purposes in wallets.",
            $comment: "Origin: String (PrimitiveType); Character strings.",
            type: "string",
        },
        image: {
            $ref: "#/$defs/Image",
        },
        credentialSubject: {
            $ref: "#/$defs/AchievementSubject",
        },
        endorsement: {
            type: "array",
            items: {
                $ref: "#/$defs/EndorsementCredential",
            },
        },
        endorsementJwt: {
            type: "array",
            items: {
                description:
                    "Allows endorsers to make specific claims about the credential, and the achievement and profiles in the credential. These endorsements are signed with the VC-JWT proof format.",
                $comment:
                    "Origin: CompactJws (DerivedType); A `String` in Compact JWS format [[RFC7515]].",
                type: "string",
                pattern: "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]+$",
            },
        },
        evidence: {
            type: "array",
            items: {
                $ref: "#/$defs/Evidence",
            },
        },
        issuer: {
            $ref: "#/$defs/Profile",
        },
        issuanceDate: {
            description: "Timestamp of when the credential was issued.",
            $comment:
                "Origin: DateTimeZ (DerivedType); A `DateTime` with the trailing timezone specifier included, e.g. `2021-09-07T02:09:59+02:00`",
            type: "string",
            format: "date-time",
        },
        expirationDate: {
            description:
                "If the credential has some notion of expiry, this indicates a timestamp when a credential should no longer be considered valid. After this time, the credential should be considered expired.",
            $comment:
                "Origin: DateTimeZ (DerivedType); A `DateTime` with the trailing timezone specifier included, e.g. `2021-09-07T02:09:59+02:00`",
            type: "string",
            format: "date-time",
        },
        awardedDate: {
            description:
                "Timestamp of when the credential was awarded. `issuanceDate` is used to determine the most recent version of a Credential in conjunction with `issuer` and `id`. Consequently, the only way to update a Credental is to update the `issuanceDate`, losing the date when the Credential was originally awarded. `awardedDate` is meant to keep this original date.",
            $comment:
                "Origin: DateTimeZ (DerivedType); A `DateTime` with the trailing timezone specifier included, e.g. `2021-09-07T02:09:59+02:00`",
            type: "string",
            format: "date-time",
        },
        proof: {
            oneOf: [
                {
                    $ref: "#/$defs/Proof",
                },
                {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Proof",
                    },
                },
            ],
        },
        credentialSchema: {
            oneOf: [
                {
                    $ref: "#/$defs/CredentialSchema",
                },
                {
                    type: "array",
                    items: {
                        $ref: "#/$defs/CredentialSchema",
                    },
                },
            ],
        },
        credentialStatus: {
            $ref: "#/$defs/CredentialStatus",
        },
        refreshService: {
            $ref: "#/$defs/RefreshService",
        },
        termsOfUse: {
            oneOf: [
                {
                    $ref: "#/$defs/TermsOfUse",
                },
                {
                    type: "array",
                    items: {
                        $ref: "#/$defs/TermsOfUse",
                    },
                },
            ],
        },
    },
    required: [
        "@context",
        "id",
        "type",
        "name",
        "credentialSubject",
        "issuer",
        "issuanceDate",
    ],
    additionalProperties: true,
    $defs: {
        Context: {
            description:
                "JSON-LD Context. Either a URI with the context definition or a Map with a local context definition MUST be supplied.",
            anyOf: [
                {
                    description:
                        "A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                {
                    description:
                        "A map representing an object with unknown, arbitrary properties",
                    $comment:
                        "Origin: Map (PrimitiveType); A map representing an object with unknown, arbitrary properties",
                    type: "object",
                },
            ],
        },
        TermsOfUse: {
            description:
                "Terms of use can be utilized by an issuer or a holder to communicate the terms under which a verifiable credential or verifiable presentation was issued",
            type: "object",
            properties: {
                id: {
                    description:
                        "The value MUST be a URI identifying the term of use.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    description:
                        "The value MUST identify the type of the terms of use.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
            },
            required: ["type"],
            additionalProperties: true,
        },
        CredentialStatus: {
            description:
                "The information in CredentialStatus is used to discover information about the current status of a verifiable credential, such as whether it is suspended or revoked.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The value MUST be the URL of the issuer's credential status method.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    description: "The name of the credential status method.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
            },
            required: ["id", "type"],
            additionalProperties: true,
        },
        AchievementSubject: {
            description:
                "A collection of information about the recipient of an achievement. Maps to Credential Subject in [[VC-DATA-MODEL]].",
            type: "object",
            properties: {
                id: {
                    description:
                        "An identifier for the Credential Subject. Either `id` or at least one `identifier` MUST be supplied.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'AchievementSubject'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'AchievementSubject'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                activityEndDate: {
                    description: "The datetime the activity ended.",
                    $comment:
                        "Origin: DateTime (PrimitiveType); An [[ISO8601]] time using the syntax YYYY-MM-DDThh:mm:ss.",
                    type: "string",
                    format: "date-time",
                },
                activityStartDate: {
                    description: "The datetime the activity started.",
                    $comment:
                        "Origin: DateTime (PrimitiveType); An [[ISO8601]] time using the syntax YYYY-MM-DDThh:mm:ss.",
                    type: "string",
                    format: "date-time",
                },
                creditsEarned: {
                    description:
                        "The number of credits earned, generally in semester or quarter credit hours. This field correlates with the Achievement `creditsAvailable` field.",
                    $comment: "Origin: Float (PrimitiveType)",
                    type: "number",
                },
                achievement: {
                    $ref: "#/$defs/Achievement",
                },
                identifier: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/IdentityObject",
                    },
                },
                image: {
                    $ref: "#/$defs/Image",
                },
                licenseNumber: {
                    description:
                        "The license number that was issued with this credential.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                narrative: {
                    description:
                        "A narrative that connects multiple pieces of evidence. Likely only present at this location if evidence is a multi-value array.",
                    $comment:
                        "Origin: Markdown (DerivedType); A `String` that may contain Markdown.",
                    type: "string",
                },
                result: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Result",
                    },
                },
                role: {
                    description:
                        "Role, position, or title of the learner when demonstrating or performing the achievement or evidence of learning being asserted. Examples include 'Student President', 'Intern', 'Captain', etc.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                source: {
                    $ref: "#/$defs/Profile",
                },
                term: {
                    description:
                        "The academic term in which this assertion was achieved.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["type", "achievement"],
            additionalProperties: true,
        },
        IdentityObject: {
            description:
                "A collection of information about the recipient of an achievement.",
            type: "object",
            properties: {
                type: {
                    description: "MUST be the IRI 'IdentityObject'.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
                hashed: {
                    description:
                        "Whether or not the `identityHash` value is hashed.",
                    $comment:
                        "Origin: Boolean (PrimitiveType); A boolean, expressed as `true` or `false`",
                    type: "boolean",
                },
                identityHash: {
                    description:
                        "Either the IdentityHash of the identity or the plaintext value. If it's possible that the plaintext transmission and storage of the identity value would leak personally identifiable information where there is an expectation of privacy, it is strongly recommended that an IdentityHash be used.",
                    $comment:
                        "Origin: IdentityHash (DerivedType); A `String` consisting of an algorithm identifier, a `$` separator, and a hash across an identifier and an optionally appended salt string. The only supported algorithms are MD5 [[RFC1321]] and SHA-256 [[FIPS-180-4]], identified by the strings 'md5' and 'sha256' respectively. Identifiers and salts MUST be encoded in UTF-8 prior to hashing, and the resulting hash MUST be expressed in hexadecimal using uppercase (A-F, 0-9) or lowercase character (a-f, 0-9) sets. For example: 'sha256$b5809d8a92f8858436d7e6b87c12ebc0ae1eac4baecc2c0b913aee2c922ef399' represents the result of calculating a SHA-256 hash on the string 'a@example.comKosher'. in which the email identifier 'a@example.com' is salted with 'Kosher'",
                    type: "string",
                },
                identityType: {
                    description: "The identity type.",
                    $comment: "Origin: IdentifierTypeEnum (EnumExt)",
                    anyOf: [
                        {
                            type: "string",
                            enum: [
                                "name",
                                "sourcedId",
                                "systemId",
                                "productId",
                                "userName",
                                "accountId",
                                "emailAddress",
                                "nationalIdentityNumber",
                                "isbn",
                                "issn",
                                "lisSourcedId",
                                "oneRosterSourcedId",
                                "sisSourcedId",
                                "ltiContextId",
                                "ltiDeploymentId",
                                "ltiToolId",
                                "ltiPlatformId",
                                "ltiUserId",
                                "identifier",
                            ],
                        },
                        {
                            type: "string",
                            pattern: "(ext:)[a-z|A-Z|0-9|.|-|_]+",
                        },
                    ],
                },
                salt: {
                    description:
                        "If the `identityHash` is hashed, this should contain the string used to salt the hash. If this value is not provided, it should be assumed that the hash was not salted.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["type", "hashed", "identityHash", "identityType"],
            additionalProperties: false,
        },
        Evidence: {
            description:
                "Descriptive metadata about evidence related to the achievement assertion. Each instance of the evidence class present in an assertion corresponds to one entity, though a single entry can describe a set of items collectively. There may be multiple evidence entries referenced from an assertion. The narrative property is also in scope of the assertion class to provide an overall description of the achievement related to the assertion in rich text. It is used here to provide a narrative of achievement of the specific entity described. If both the description and narrative properties are present, displayers can assume the narrative value goes into more detail and is not simply a recapitulation of description.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The URL of a webpage presenting evidence of achievement or the evidence encoded as a Data URI. The schema of the webpage is undefined.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Evidence'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Evidence'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                narrative: {
                    description:
                        "A narrative that describes the evidence and process of achievement that led to an assertion.",
                    $comment:
                        "Origin: Markdown (DerivedType); A `String` that may contain Markdown.",
                    type: "string",
                },
                name: {
                    description: "A descriptive title of the evidence.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                description: {
                    description: "A longer description of the evidence.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                genre: {
                    description:
                        "A string that describes the type of evidence. For example, Poetry, Prose, Film.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                audience: {
                    description:
                        "A description of the intended audience for a piece of evidence.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["type"],
            additionalProperties: true,
        },
        EndorsementCredential: {
            description:
                "A verifiable credential that asserts a claim about an entity. As described in [[[#data-integrity]]], at least one proof mechanism, and the details necessary to evaluate that proof, MUST be expressed for a credential to be a verifiable credential. In the case of an embedded proof, the credential MUST append the proof in the `proof` property.",
            type: "object",
            properties: {
                "@context": {
                    type: "array",
                    minItems: 1,
                    items: {
                        $ref: "#/$defs/Context",
                    },
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the URI 'VerifiableCredential', and one of the items MUST be the URI 'EndorsementCredential'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the URI 'VerifiableCredential', and one of the items MUST be the URI 'EndorsementCredential'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                id: {
                    description: "Unambiguous reference to the credential.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                name: {
                    description:
                        "The name of the credential for display purposes in wallets. For example, in a list of credentials and in detail views.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                description: {
                    description:
                        "The short description of the credential for display purposes in wallets.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                credentialSubject: {
                    $ref: "#/$defs/EndorsementSubject",
                },
                issuer: {
                    $ref: "#/$defs/Profile",
                },
                issuanceDate: {
                    description: "Timestamp of when the credential was issued.",
                    $comment:
                        "Origin: DateTimeZ (DerivedType); A `DateTime` with the trailing timezone specifier included, e.g. `2021-09-07T02:09:59+02:00`",
                    type: "string",
                    format: "date-time",
                },
                expirationDate: {
                    description:
                        "If the credential has some notion of expiry, this indicates a timestamp when a credential should no longer be considered valid. After this time, the credential should be considered expired.",
                    $comment:
                        "Origin: DateTimeZ (DerivedType); A `DateTime` with the trailing timezone specifier included, e.g. `2021-09-07T02:09:59+02:00`",
                    type: "string",
                    format: "date-time",
                },
                awardedDate: {
                    description:
                        "Timestamp of when the credential was awarded. `issuanceDate` is used to determine the most recent version of a Credential in conjunction with `issuer` and `id`. Consequently, the only way to update a Credental is to update the `issuanceDate`, losing the date when the Credential was originally awarded. `awardedDate` is meant to keep this original date.",
                    $comment:
                        "Origin: DateTimeZ (DerivedType); A `DateTime` with the trailing timezone specifier included, e.g. `2021-09-07T02:09:59+02:00`",
                    type: "string",
                    format: "date-time",
                },
                proof: {
                    oneOf: [
                        {
                            $ref: "#/$defs/Proof",
                        },
                        {
                            type: "array",
                            items: {
                                $ref: "#/$defs/Proof",
                            },
                        },
                    ],
                },
                credentialSchema: {
                    oneOf: [
                        {
                            $ref: "#/$defs/CredentialSchema",
                        },
                        {
                            type: "array",
                            items: {
                                $ref: "#/$defs/CredentialSchema",
                            },
                        },
                    ],
                },
                credentialStatus: {
                    $ref: "#/$defs/CredentialStatus",
                },
                refreshService: {
                    $ref: "#/$defs/RefreshService",
                },
                termsOfUse: {
                    oneOf: [
                        {
                            $ref: "#/$defs/TermsOfUse",
                        },
                        {
                            type: "array",
                            items: {
                                $ref: "#/$defs/TermsOfUse",
                            },
                        },
                    ],
                },
            },
            required: [
                "@context",
                "type",
                "id",
                "name",
                "credentialSubject",
                "issuer",
                "issuanceDate",
            ],
            additionalProperties: true,
        },
        Achievement: {
            description:
                "A collection of information about the accomplishment recognized by the Assertion. Many assertions may be created corresponding to one Achievement.",
            type: "object",
            properties: {
                id: {
                    description: "Unique URI for the Achievement.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description: "No description supplied.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description: "No description supplied.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                alignment: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Alignment",
                    },
                },
                achievementType: {
                    description:
                        "The type of achievement. This is an extensible vocabulary.",
                    $comment:
                        "Origin: AchievementType (EnumExt); The type of achievement, for example 'Award' or 'Certification'. This is an extensible enumerated vocabulary. Extending the vocabulary makes use of a naming convention.",
                    anyOf: [
                        {
                            type: "string",
                            enum: [
                                "Achievement",
                                "ApprenticeshipCertificate",
                                "Assessment",
                                "Assignment",
                                "AssociateDegree",
                                "Award",
                                "Badge",
                                "BachelorDegree",
                                "Certificate",
                                "CertificateOfCompletion",
                                "Certification",
                                "CommunityService",
                                "Competency",
                                "Course",
                                "CoCurricular",
                                "Degree",
                                "Diploma",
                                "DoctoralDegree",
                                "Fieldwork",
                                "GeneralEducationDevelopment",
                                "JourneymanCertificate",
                                "LearningProgram",
                                "License",
                                "Membership",
                                "ProfessionalDoctorate",
                                "QualityAssuranceCredential",
                                "MasterCertificate",
                                "MasterDegree",
                                "MicroCredential",
                                "ResearchDoctorate",
                                "SecondarySchoolDiploma",
                            ],
                        },
                        {
                            type: "string",
                            pattern: "(ext:)[a-z|A-Z|0-9|.|-|_]+",
                        },
                    ],
                },
                creator: {
                    $ref: "#/$defs/Profile",
                },
                creditsAvailable: {
                    description:
                        "Credit hours associated with this entity, or credit hours possible. For example 3.0.",
                    $comment: "Origin: Float (PrimitiveType)",
                    type: "number",
                },
                criteria: {
                    $ref: "#/$defs/Criteria",
                },
                description: {
                    description: "A short description of the achievement.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                endorsement: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/EndorsementCredential",
                    },
                },
                endorsementJwt: {
                    type: "array",
                    items: {
                        description:
                            "Allows endorsers to make specific claims about the Achievement. These endorsements are signed with the VC-JWT proof format.",
                        $comment:
                            "Origin: CompactJws (DerivedType); A `String` in Compact JWS format [[RFC7515]].",
                        type: "string",
                        pattern:
                            "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]+$",
                    },
                },
                fieldOfStudy: {
                    description:
                        "Category, subject, area of study, discipline, or general branch of knowledge. Examples include Business, Education, Psychology, and Technology.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                humanCode: {
                    description:
                        "The code, generally human readable, associated with an achievement.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                image: {
                    $ref: "#/$defs/Image",
                },
                "@language": {
                    description: "The language of the achievement.",
                    $comment:
                        "Origin: LanguageCode (DerivedType); A language code [[BCP47]].",
                    type: "string",
                    pattern:
                        "^[a-z]{2,4}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$",
                },
                name: {
                    description: "The name of the achievement.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                otherIdentifier: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/IdentifierEntry",
                    },
                },
                related: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Related",
                    },
                },
                resultDescription: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/ResultDescription",
                    },
                },
                specialization: {
                    description:
                        "Name given to the focus, concentration, or specific area of study defined in the achievement. Examples include 'Entrepreneurship', 'Technical Communication', and 'Finance'.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                tag: {
                    type: "array",
                    items: {
                        description:
                            "One or more short, human-friendly, searchable, keywords that describe the type of achievement.",
                        $comment:
                            "Origin: String (PrimitiveType); Character strings.",
                        type: "string",
                    },
                },
                version: {
                    description:
                        "The version property allows issuers to set a version string for an Achievement. This is particularly useful when replacing a previous version with an update.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["id", "type", "criteria", "description", "name"],
            additionalProperties: true,
        },
        Alignment: {
            description:
                "Describes an alignment between an achievement and a node in an educational framework.",
            type: "object",
            properties: {
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Alignment'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Alignment'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                targetCode: {
                    description:
                        "If applicable, a locally unique string identifier that identifies the alignment target within its framework and/or targetUrl.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                targetDescription: {
                    description: "Short description of the alignment target.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                targetName: {
                    description: "Name of the alignment.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                targetFramework: {
                    description: "Name of the framework the alignment target.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                targetType: {
                    description: "The type of the alignment target node.",
                    $comment:
                        "Origin: AlignmentTargetType (EnumExt); The type of the alignment target node in the target framework.",
                    anyOf: [
                        {
                            type: "string",
                            enum: [
                                "ceasn:Competency",
                                "ceterms:Credential",
                                "CFItem",
                                "CFRubric",
                                "CFRubricCriterion",
                                "CFRubricCriterionLevel",
                                "CTDL",
                            ],
                        },
                        {
                            type: "string",
                            pattern: "(ext:)[a-z|A-Z|0-9|.|-|_]+",
                        },
                    ],
                },
                targetUrl: {
                    description:
                        "URL linking to the official description of the alignment target, for example an individual standard within an educational framework.",
                    $comment:
                        "Origin: URL (DerivedType); A `URI` that represents a Uniform Resource Locator (URL).",
                    type: "string",
                },
            },
            required: ["type", "targetName", "targetUrl"],
            additionalProperties: true,
        },
        Criteria: {
            description:
                "Descriptive metadata about the achievements necessary to be recognized with an assertion of a particular achievement. This data is added to the Achievement class so that it may be rendered when the achievement assertion is displayed, instead of simply a link to human-readable criteria external to the achievement. Embedding criteria allows either enhancement of an external criteria page or increased portability and ease of use by allowing issuers to skip hosting the formerly-required external criteria page altogether. Criteria is used to allow would-be recipients to learn what is required of them to be recognized with an assertion of a particular achievement. It is also used after the assertion is awarded to a recipient to let those inspecting earned achievements know the general requirements that the recipients met in order to earn it.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The URI of a webpage that describes in a human-readable format the criteria for the achievement.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                narrative: {
                    description:
                        "A narrative of what is needed to earn the achievement. Markdown is allowed.",
                    $comment:
                        "Origin: Markdown (DerivedType); A `String` that may contain Markdown.",
                    type: "string",
                },
            },
            required: [],
            additionalProperties: true,
        },
        IdentifierEntry: {
            description: "No description supplied.",
            type: "object",
            properties: {
                type: {
                    description:
                        "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'IdentifierEntry'.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
                identifier: {
                    description: "An identifier.",
                    $comment:
                        "Origin: Identifier (DerivedType); A `NormalizedString` that functions as an identifier.",
                    type: "string",
                },
                identifierType: {
                    description: "The identifier type.",
                    $comment: "Origin: IdentifierTypeEnum (EnumExt)",
                    anyOf: [
                        {
                            type: "string",
                            enum: [
                                "name",
                                "sourcedId",
                                "systemId",
                                "productId",
                                "userName",
                                "accountId",
                                "emailAddress",
                                "nationalIdentityNumber",
                                "isbn",
                                "issn",
                                "lisSourcedId",
                                "oneRosterSourcedId",
                                "sisSourcedId",
                                "ltiContextId",
                                "ltiDeploymentId",
                                "ltiToolId",
                                "ltiPlatformId",
                                "ltiUserId",
                                "identifier",
                            ],
                        },
                        {
                            type: "string",
                            pattern: "(ext:)[a-z|A-Z|0-9|.|-|_]+",
                        },
                    ],
                },
            },
            required: ["type", "identifier", "identifierType"],
            additionalProperties: false,
        },
        Proof: {
            description: "A JSON-LD Linked Data proof.",
            type: "object",
            properties: {
                type: {
                    description: "Signature suite used to produce proof.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
                created: {
                    description: "Date the proof was created.",
                    $comment:
                        "Origin: DateTime (PrimitiveType); An [[ISO8601]] time using the syntax YYYY-MM-DDThh:mm:ss.",
                    type: "string",
                    format: "date-time",
                },
                cryptosuite: {
                    description: "The suite used to create the proof.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                challenge: {
                    description:
                        "A value chosen by the verifier to mitigate authentication proof replay attacks.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                domain: {
                    description:
                        "The domain of the proof to restrict its use to a particular target.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                nonce: {
                    description:
                        "A value chosen by the creator of proof to randomize proof values for privacy purposes.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                proofPurpose: {
                    description:
                        "The purpose of the proof to be used with `verificationMethod`. MUST be 'assertionMethod'.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                proofValue: {
                    description: "Value of the proof.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                verificationMethod: {
                    description:
                        "The URL of the public key that can verify the signature.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
            },
            required: ["type"],
            additionalProperties: true,
        },
        RefreshService: {
            description:
                "The information in RefreshService is used to refresh the verifiable credential.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The value MUST be the URL of the issuer's refresh service.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    description: "The name of the refresh service method.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
            },
            required: ["id", "type"],
            additionalProperties: true,
        },
        Image: {
            description:
                "Metadata about images that represent assertions, achieve or profiles. These properties can typically be represented as just the id string of the image, but using a fleshed-out document allows for including captions and other applicable metadata.",
            type: "object",
            properties: {
                id: {
                    description: "The URI or Data URI of the image.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    description: "MUST be the IRI 'Image'.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
                caption: {
                    description: "The caption for the image.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["id", "type"],
            additionalProperties: false,
        },
        EndorsementSubject: {
            description:
                "A collection of information about the subject of the endorsement.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The identifier of the individual, entity, organization, assertion, or achievement that is endorsed.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the URI 'VerifiableCredential', and one of the items MUST be the URI 'EndorsementSubject'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the URI 'VerifiableCredential', and one of the items MUST be the URI 'EndorsementSubject'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                endorsementComment: {
                    description:
                        "Allows endorsers to make a simple claim in writing about the entity.",
                    $comment:
                        "Origin: Markdown (DerivedType); A `String` that may contain Markdown.",
                    type: "string",
                },
            },
            required: ["id", "type"],
            additionalProperties: true,
        },
        Result: {
            description: "Describes a result that was achieved.",
            type: "object",
            properties: {
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Result'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Result'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                achievedLevel: {
                    description:
                        "If the result represents an achieved rubric criterion level (e.g. Mastered), the value is the `id` of the RubricCriterionLevel in linked ResultDescription.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                alignment: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Alignment",
                    },
                },
                resultDescription: {
                    description:
                        "An achievement can have many result descriptions describing possible results. The value of `resultDescription` is the `id` of the result description linked to this result. The linked result description must be in the achievement that is being asserted.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                status: {
                    description:
                        "The status of the achievement. Required if `resultType` of the linked ResultDescription is Status.",
                    $comment:
                        "Origin: ResultStatusType (Enumeration); Defined vocabulary to convey the status of an achievement.",
                    type: "string",
                    enum: [
                        "Completed",
                        "Enrolled",
                        "Failed",
                        "InProgress",
                        "OnHold",
                        "Withdrew",
                    ],
                },
                value: {
                    description:
                        "A string representing the result of the performance, or demonstration, of the achievement. For example, 'A' if the recipient received an A grade in class.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["type"],
            additionalProperties: true,
        },
        ResultDescription: {
            description: "Describes a possible achievement result.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The unique URI for this result description. Required so a result can link to this result description.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'ResultDescription'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'ResultDescription'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                alignment: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Alignment",
                    },
                },
                allowedValue: {
                    type: "array",
                    items: {
                        description:
                            "An ordered list of allowed values. The values should be ordered from low to high as determined by the achievement creator.",
                        $comment:
                            "Origin: String (PrimitiveType); Character strings.",
                        type: "string",
                    },
                },
                name: {
                    description: "The name of the result.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                requiredLevel: {
                    description:
                        "The `id` of the rubric criterion level required to pass as determined by the achievement creator.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                requiredValue: {
                    description:
                        "A value from `allowedValue` or within the range of `valueMin` to `valueMax` required to pass as determined by the achievement creator.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                resultType: {
                    description:
                        "The type of result this description represents. This is an extensible enumerated vocabulary.",
                    $comment:
                        "Origin: ResultType (EnumExt); The type of result. This is an extensible enumerated vocabulary. Extending the vocabulary makes use of a naming convention.",
                    anyOf: [
                        {
                            type: "string",
                            enum: [
                                "GradePointAverage",
                                "LetterGrade",
                                "Percent",
                                "PerformanceLevel",
                                "PredictedScore",
                                "RawScore",
                                "Result",
                                "RubricCriterion",
                                "RubricCriterionLevel",
                                "RubricScore",
                                "ScaledScore",
                                "Status",
                            ],
                        },
                        {
                            type: "string",
                            pattern: "(ext:)[a-z|A-Z|0-9|.|-|_]+",
                        },
                    ],
                },
                rubricCriterionLevel: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/RubricCriterionLevel",
                    },
                },
                valueMax: {
                    description:
                        "The maximum possible `value` that may be asserted in a linked result.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                valueMin: {
                    description:
                        "The minimum possible `value` that may be asserted in a linked result.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["id", "type", "name", "resultType"],
            additionalProperties: true,
        },
        RubricCriterionLevel: {
            description: "Describes a rubric criterion level.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The unique URI for this rubric criterion level. Required so a result can link to this rubric criterion level.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'RubricCriterionLevel'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'RubricCriterionLevel'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                alignment: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/Alignment",
                    },
                },
                description: {
                    description: "Description of the rubric criterion level.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                level: {
                    description:
                        "The rubric performance level in terms of success.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                name: {
                    description: "The name of the rubric criterion level.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                points: {
                    description:
                        "The points associated with this rubric criterion level.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["id", "type", "name"],
            additionalProperties: true,
        },
        Related: {
            description: "Identifies a related achievement.",
            type: "object",
            properties: {
                id: {
                    description: "The related achievement.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Related'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Related'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                "@language": {
                    description: "The language of the related achievement.",
                    $comment:
                        "Origin: LanguageCode (DerivedType); A language code [[BCP47]].",
                    type: "string",
                    pattern:
                        "^[a-z]{2,4}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$",
                },
                version: {
                    description: "The version of the related achievement.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
            },
            required: ["id", "type"],
            additionalProperties: true,
        },
        Profile: {
            description:
                "A Profile is a collection of information that describes the entity or organization using Open Badges. Issuers must be represented as Profiles, and endorsers, or other entities may also be represented using this vocabulary. Each Profile that represents an Issuer may be referenced in many BadgeClasses that it has defined. Anyone can create and host an Issuer file to start issuing Open Badges. Issuers may also serve as recipients of Open Badges, often identified within an Assertion by specific properties, like their url or contact email address.",
            type: "object",
            properties: {
                id: {
                    description: "Unique URI for the Issuer/Profile file.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Profile'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Profile'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                name: {
                    description: "The name of the entity or organization.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                url: {
                    description:
                        "The homepage or social media profile of the entity, whether individual or institutional. Should be a URL/URI Accessible via HTTP.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                phone: {
                    description: "A phone number.",
                    $comment:
                        "Origin: PhoneNumber (DerivedType); A `NormalizedString` representing a phone number.",
                    type: "string",
                },
                description: {
                    description:
                        "A short description of the issuer entity or organization.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                endorsement: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/EndorsementCredential",
                    },
                },
                endorsementJwt: {
                    type: "array",
                    items: {
                        description:
                            "Allows endorsers to make specific claims about the individual or organization represented by this profile. These endorsements are signed with the VC-JWT proof format.",
                        $comment:
                            "Origin: CompactJws (DerivedType); A `String` in Compact JWS format [[RFC7515]].",
                        type: "string",
                        pattern:
                            "^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]+$",
                    },
                },
                image: {
                    $ref: "#/$defs/Image",
                },
                email: {
                    description: "An email address.",
                    $comment:
                        "Origin: EmailAddress (DerivedType); A `NormalizedString` representing an email address.",
                    type: "string",
                },
                address: {
                    $ref: "#/$defs/Address",
                },
                otherIdentifier: {
                    type: "array",
                    items: {
                        $ref: "#/$defs/IdentifierEntry",
                    },
                },
                official: {
                    description:
                        "If the entity is an organization, `official` is the name of an authorized official of the organization.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                parentOrg: {
                    $ref: "#/$defs/Profile",
                },
                familyName: {
                    description:
                        "Family name. In the western world, often referred to as the 'last name' of a person.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                givenName: {
                    description:
                        "Given name. In the western world, often referred to as the 'first name' of a person.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                additionalName: {
                    description:
                        "Additional name. Includes what is often referred to as 'middle name' in the western world.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                patronymicName: {
                    description: "Patronymic name.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                honorificPrefix: {
                    description:
                        "Honorific prefix(es) preceding a person's name (e.g. 'Dr', 'Mrs' or 'Mr').",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                honorificSuffix: {
                    description:
                        "Honorific suffix(es) following a person's name (e.g. 'M.D, PhD').",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                familyNamePrefix: {
                    description:
                        "Family name prefix. As used in some locales, this is the leading part of a family name (e.g. 'de' in the name 'de Boer').",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                dateOfBirth: {
                    description: "Birthdate of the person.",
                    $comment:
                        "Origin: Date (PrimitiveType); An [[ISO8601]] calendar date using the syntax YYYY-MM-DD.",
                    type: "string",
                    format: "date",
                },
            },
            required: ["id", "type"],
            additionalProperties: true,
        },
        Address: {
            description: "An address for the described entity.",
            type: "object",
            properties: {
                type: {
                    oneOf: [
                        {
                            description:
                                "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Address'.",
                            $comment:
                                "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                            type: "string",
                        },
                        {
                            type: "array",
                            minItems: 1,
                            items: {
                                description:
                                    "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'Address'.",
                                $comment:
                                    "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                                type: "string",
                            },
                        },
                    ],
                },
                addressCountry: {
                    description: "A country.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                addressCountryCode: {
                    description:
                        "A country code. The value must be a ISO 3166-1 alpha-2 country code [[ISO3166-1]].",
                    $comment:
                        "Origin: CountryCode (DerivedType); A two-digit ISO 3166-1 alpha-2 country code [[ISO3166-1]].",
                    type: "string",
                },
                addressRegion: {
                    description: "A region within the country.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                addressLocality: {
                    description: "A locality within the region.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                streetAddress: {
                    description: "A street address within the locality.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                postOfficeBoxNumber: {
                    description:
                        "A post office box number for PO box addresses.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                postalCode: {
                    description: "A postal code.",
                    $comment:
                        "Origin: String (PrimitiveType); Character strings.",
                    type: "string",
                },
                geo: {
                    $ref: "#/$defs/GeoCoordinates",
                },
            },
            required: ["type"],
            additionalProperties: true,
        },
        GeoCoordinates: {
            description: "The geographic coordinates of a location.",
            type: "object",
            properties: {
                type: {
                    description:
                        "The value of the type property MUST be an unordered set. One of the items MUST be the IRI 'GeoCoordinates'.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
                latitude: {
                    description: "The latitude of the location [[WGS84]].",
                    $comment: "Origin: Float (PrimitiveType)",
                    type: "number",
                },
                longitude: {
                    description: "The longitude of the location [[WGS84]].",
                    $comment: "Origin: Float (PrimitiveType)",
                    type: "number",
                },
            },
            required: ["type", "latitude", "longitude"],
            additionalProperties: true,
        },
        CredentialSchema: {
            description: "Identify the type and location of a data schema.",
            type: "object",
            properties: {
                id: {
                    description:
                        "The value MUST be a URI identifying the schema file. One instance of `CredentialSchema` MUST have an `id` that is the URL of the JSON Schema for this credential defined by this specification.",
                    $comment:
                        "Origin: URI (DerivedType); A `NormalizedString` that respresents a Uniform Resource Identifier (URI).",
                    type: "string",
                },
                type: {
                    description:
                        "The value MUST identify the type of data schema validation. One instance of `CredentialSchema` MUST have a `type` of 'JsonSchemaValidator2019'.",
                    $comment:
                        "Origin: IRI (DerivedType); A `NormalizedString` that represents an Internationalized Resource Identifier (IRI), which extends the ASCII characters subset of the Uniform Resource Identifier (URI).",
                    type: "string",
                },
            },
            required: ["id", "type"],
            additionalProperties: true,
        },
    },
};
