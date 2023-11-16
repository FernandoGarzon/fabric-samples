package chaincode

// This file simply sets a single variable, which contains the meta-schema
// that will be used to validate all submitted schemas.
//
// The meta-schema is multiline and a bit messy to cram into code, so we
// store it here to make updates easier and less error-prone.
const metaschemaText = `
{
    "id" : "tag:schema.opensciencechain.org,2023-05-01:meta-1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "Meta-Schema for validating OSC-IS JSON Schemas",
    "properties": {
       "$schema" : {
         "description" : "The JSON Schema version to use for validation.",
         "type": "string",
         "pattern" : "^http[s]://json-schema\\.org"
       },
       "id" : {
         "description": "The ID field",
         "type" : "string",
         "pattern" : "^tag:schema\\.opensciencechain\\.org,"
       },
       "description" : {
         "description" : "A description of the schema",
         "type" : "string"
       },
       "properties" : {
         "description" : "A list of properties",
         "type" : "object",
         "properties" : {
           "mandatory_public_fields" : {
             "description" : "Minimal fields required for the public component of all OSC-IS Artifacts.",
             "type" : "object",
             "properties" : {
               "type" : {
                 "type" : "string"
               },
               "properties" : {
                 "type" : "object",
                 "properties" : {
                   "title": {
                     "type": "object",
                     "properties" : {
                       "type" : { "type" : "string" },
                       "description" : { "type" : "string" },
                       "minLength" :  { "type" : "integer", "minimum" : 1 }
                     },
                     "required" : [ "type", "description", "minLength" ]
                   },
                   "description": {
                     "type": "object",
                     "properties" : {
                       "type" : { "type" : "string" },
                       "description" : { "type" : "string" },
                       "minLength" :  { "type" : "integer", "minimum" : 1 }
                     },
                     "required" : [ "type", "description", "minLength" ]
                   },
                   "submission_comment": {
                     "type": "object",
                     "properties" : {
                       "type" : { "type" : "string" },
                       "description" : { "type" : "string" },
                       "minLength" :  { "type" : "integer", "minimum" : 1 }
                     },
                     "required" : [ "type", "description", "minLength" ]
                   }
                 },
                 "required" : [ "title", "description", "submission_comment" ]
               },
               "required" : {
                 "type" : "array"
               }
            },
            "unevaluatedProperties" : false
          },
          "public_fields": {
            "description" : "Fields which will be forever readable without authentication.",
            "type" : "object"
          },
          "private_fields": {
            "description" : "Fields which will only be readable by members of the same group as this schema.",
            "type" : "object"
          }
        },
        "required" : [ "mandatory_public_fields", "public_fields", "private_fields" ]
      }
    },
    "required" : [ "$schema", "id", "description", "properties" ],
    "unevaluatedProperties": false
}
`
