#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { google } from 'googleapis';
import { authenticate } from "@google-cloud/local-auth";
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOKEN_PATH = path.join(__dirname, "tokens.json");
const CLIENT_CREDENTIALS_PATH = path.join(__dirname, "credentials.json");

// Load the client credentials from the JSON file
async function loadClientCredentials() {
  console.error('Loading client credentials from:', CLIENT_CREDENTIALS_PATH);
  try {
    const credentialsContent = await fs.readFile(CLIENT_CREDENTIALS_PATH, 'utf8');
    return JSON.parse(credentialsContent).web;
  } catch (error) {
    console.error('Failed to load client credentials:', error.message);
    throw new Error(`Failed to load client credentials: ${error.message}`);
  }
}

async function authenticateAndSaveCredentials() {
  console.error('Starting authentication process...');
  const credentials = await loadClientCredentials();
  console.error('Client credentials loaded successfully:', credentials.client_id);

  console.error('Launching OAuth2 flow with @google-cloud/local-auth...');
  const auth = await authenticate({
    keyfilePath: CLIENT_CREDENTIALS_PATH,
    scopes: [
      'https://www.googleapis.com/auth/classroom.courses.readonly',
      'https://www.googleapis.com/auth/classroom.announcements.readonly',
      'https://www.googleapis.com/auth/classroom.coursework.me.readonly',
      'https://www.googleapis.com/auth/classroom.rosters.readonly'
    ],
  });

  console.error('Authentication successful, saving credentials to:', TOKEN_PATH);
  await fs.writeFile(TOKEN_PATH, JSON.stringify(auth.credentials));
  console.error('Credentials saved successfully.');
  return auth;
}

// Create a Google Auth client from env vars
function createGoogleAuthFromEnv(refreshToken) {
  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET
  );
  auth.setCredentials({ refresh_token: refreshToken });
  return auth;
}

// Load credentials from file (for stdio/local mode)
async function loadCredentialsFromFile() {
  console.error('Checking for saved credentials at:', TOKEN_PATH);
  if (!await fs.access(TOKEN_PATH).then(() => true).catch(() => false)) {
    console.error('Credentials file does not exist.');
    throw new Error('Credentials not found. Please run with "auth" argument first.');
  }
  console.error('Credentials file found, loading...');
  let credentials;
  try {
    credentials = JSON.parse(await fs.readFile(TOKEN_PATH, 'utf-8'));
  } catch (error) {
    console.error('Failed to parse credentials:', error.message);
    throw new Error('Failed to parse credentials: Invalid JSON in tokens.json');
  }
  console.error('Credentials loaded:', credentials.access_token ? 'Access token present' : 'No access token');

  const auth = new google.auth.OAuth2();
  auth.setCredentials(credentials);

  // Handle token refresh
  auth.on('tokens', async (tokens) => {
    console.error('Received new tokens from Google Auth Library');
    if (tokens.refresh_token) {
      console.error('Updating refresh token in saved credentials');
      const existingCredentials = JSON.parse(await fs.readFile(TOKEN_PATH, 'utf-8'));
      existingCredentials.refresh_token = tokens.refresh_token;
      await fs.writeFile(TOKEN_PATH, JSON.stringify(existingCredentials));
    }
    if (tokens.access_token) {
      console.error('Updating access token in saved credentials');
      const existingCredentials = JSON.parse(await fs.readFile(TOKEN_PATH, 'utf-8'));
      existingCredentials.access_token = tokens.access_token;
      existingCredentials.expiry_date = tokens.expiry_date;
      await fs.writeFile(TOKEN_PATH, JSON.stringify(existingCredentials));
    }
  });

  return auth;
}

function registerTools(server, getClassroomClient) {
  server.tool("add",
    { a: z.number(), b: z.number() },
    async ({ a, b }) => ({
      content: [{ type: "text", text: String(a + b) }]
    })
  );

  server.tool("courses",
    {},
    async () => {
      try {
        console.error('Attempting to fetch courses...');
        const classroom = await getClassroomClient();
        console.error('Classroom client initialized, fetching courses...');
        const courses = await classroom.courses.list();
        console.error('Courses fetched successfully:', courses.data.courses?.length || 0, 'courses found');
        return {
          content: [{ type: "text", text: JSON.stringify(courses.data) }]
        };
      } catch (error) {
        console.error('Error fetching courses:', error.message);
        if (error.message.includes('Credentials not found')) {
          return {
            content: [{
              type: "text",
              text: "Authentication required. Please run the script with the 'auth' argument to authenticate: `node script.js auth`"
            }]
          };
        }
        if (error.message.includes('access_denied')) {
          return {
            content: [{
              type: "text",
              text: "Authentication failed: This app is in testing mode. Ensure your account is added as a test user in the Google Cloud Console under OAuth consent screen > Test users."
            }]
          };
        }
        return {
          content: [{ type: "text", text: `Error fetching courses: ${error.message}` }]
        };
      }
    }
  );

  server.tool("course-details",
    { courseId: z.string().describe("The ID of the course to get details for") },
    async ({ courseId }) => {
      try {
        console.error(`Attempting to fetch details for course ${courseId}...`);
        const classroom = await getClassroomClient();

        console.error('Fetching course details...');
        let courseDetails;
        try {
          courseDetails = await classroom.courses.get({ id: courseId });
          console.error('Course details fetched successfully');
        } catch (courseError) {
          console.error('Error fetching course details:', courseError.message);
          throw new Error(`Failed to fetch course details: ${courseError.message}`);
        }

        console.error('Fetching course announcements...');
        let announcements = { data: { announcements: [] } };
        try {
          announcements = await classroom.courses.announcements.list({
            courseId: courseId,
            pageSize: 20
          });
          console.error(`Announcements fetched successfully: ${announcements.data.announcements?.length || 0} found`);
        } catch (announcementError) {
          console.error('Error fetching announcements:', announcementError.message);
          if (announcementError.message.includes('permission')) {
            console.error('Permission error accessing announcements. Check your OAuth scopes.');
          }
        }

        const result = {
          courseDetails: courseDetails.data,
          announcements: announcements.data.announcements || [],
          note: announcements.data.announcements ? "" : "No announcements available or insufficient permissions to access them."
        };

        console.error(`Details for course ${courseId} fetched successfully`);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        console.error(`Error fetching details for course ${courseId}:`, error.message);

        if (error.message.includes('Credentials not found')) {
          return {
            content: [{
              type: "text",
              text: "Authentication required. Please run the script with the 'auth' argument to authenticate: `node script.js auth`"
            }]
          };
        }

        if (error.message.includes('permission') || error.message.includes('access_denied')) {
          return {
            content: [{
              type: "text",
              text: "Permission denied. You need to re-authenticate with the proper scopes. Please run the script with the 'auth' argument: `node script.js auth` and ensure you grant all requested permissions."
            }]
          };
        }

        if (error.message.includes('not found')) {
          return {
            content: [{
              type: "text",
              text: `Course with ID ${courseId} not found. Please check the course ID and try again.`
            }]
          };
        }

        return {
          content: [{ type: "text", text: `Error fetching course details: ${error.message}` }]
        };
      }
    }
  );

  server.tool("assignments",
    {
      courseId: z.string().describe("The ID of the course to get assignments for")
    },
    async ({ courseId }) => {
      try {
        console.error(`Attempting to fetch assignments for course ${courseId}...`);
        const classroom = await getClassroomClient();

        try {
          await classroom.courses.get({ id: courseId });
          console.error('Course verified successfully');
        } catch (courseError) {
          console.error('Error verifying course:', courseError.message);
          throw new Error(`Failed to verify course: ${courseError.message}`);
        }

        console.error('Fetching course assignments...');
        let courseWork;
        try {
          courseWork = await classroom.courses.courseWork.list({
            courseId: courseId,
            pageSize: 50,
            orderBy: 'dueDate desc'
          });
          console.error(`Assignments fetched successfully: ${courseWork.data.courseWork?.length || 0} found`);
        } catch (workError) {
          console.error('Error fetching assignments:', workError.message);
          throw new Error(`Failed to fetch assignments: ${workError.message}`);
        }

        let submissions = [];
        try {
          if (courseWork.data.courseWork && courseWork.data.courseWork.length > 0) {
            console.error('Fetching your submissions for assignments...');
            const assignmentsToCheck = courseWork.data.courseWork.slice(0, 5);

            for (const work of assignmentsToCheck) {
              try {
                const submissionResponse = await classroom.courses.courseWork.studentSubmissions.list({
                  courseId: courseId,
                  courseWorkId: work.id,
                  states: ['TURNED_IN', 'RETURNED', 'RECLAIMED_BY_STUDENT']
                });

                if (submissionResponse.data.studentSubmissions) {
                  submissions = submissions.concat(submissionResponse.data.studentSubmissions);
                }
              } catch (submissionError) {
                console.error(`Error fetching submissions for assignment ${work.id}:`, submissionError.message);
              }
            }
            console.error(`Submissions fetched: ${submissions.length} found`);
          }
        } catch (submissionsError) {
          console.error('Error in submissions process:', submissionsError.message);
        }

        const result = {
          courseId: courseId,
          assignments: courseWork.data.courseWork || [],
          yourSubmissions: submissions.length > 0 ? submissions : [],
          summary: {
            totalAssignments: courseWork.data.courseWork?.length || 0,
            submissionsFound: submissions.length
          }
        };

        console.error(`Assignments data for course ${courseId} fetched successfully`);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      } catch (error) {
        console.error(`Error fetching assignments for course ${courseId}:`, error.message);

        if (error.message.includes('Credentials not found')) {
          return {
            content: [{
              type: "text",
              text: "Authentication required. Please run the script with the 'auth' argument to authenticate: `node script.js auth`"
            }]
          };
        }

        if (error.message.includes('permission') || error.message.includes('access_denied')) {
          return {
            content: [{
              type: "text",
              text: "Permission denied accessing assignments. You need to re-authenticate with the proper scopes. Please run the script with the 'auth' argument: `node script.js auth` and ensure you grant all requested permissions."
            }]
          };
        }

        if (error.message.includes('not found')) {
          return {
            content: [{
              type: "text",
              text: `Course with ID ${courseId} not found. Please check the course ID and try again.`
            }]
          };
        }

        return {
          content: [{ type: "text", text: `Error fetching assignments: ${error.message}` }]
        };
      }
    }
  );
}

// Create an MCP server configured for a specific Google Auth client
function createMcpServerWithAuth(googleAuth) {
  const server = new McpServer({ name: "class", version: "1.0.0" });
  const getClassroomClient = async () => google.classroom({ version: 'v1', auth: googleAuth });
  registerTools(server, getClassroomClient);
  return server;
}

// Parse USER_<NAME>_PASSWORD and USER_<NAME>_GOOGLE_REFRESH_TOKEN from env vars
function parseUsersFromEnv() {
  const users = new Map();
  const userPattern = /^USER_(.+)_PASSWORD$/;

  for (const [key, value] of Object.entries(process.env)) {
    const match = key.match(userPattern);
    if (match) {
      const userName = match[1].toLowerCase();
      const refreshToken = process.env[`USER_${match[1]}_GOOGLE_REFRESH_TOKEN`];
      if (!refreshToken) {
        console.error(`Warning: USER_${match[1]}_PASSWORD is set but USER_${match[1]}_GOOGLE_REFRESH_TOKEN is missing — skipping user ${userName}`);
        continue;
      }
      users.set(userName, { password: value, refreshToken });
      console.error(`Loaded user: ${userName}`);
    }
  }

  return users;
}

async function main() {
  if (process.argv[2] === "auth") {
    try {
      await authenticateAndSaveCredentials();
      console.error("Credentials saved. You can now run the server without the 'auth' argument.");
      process.exit(0);
    } catch (error) {
      console.error('Authentication failed:', error.message);
      process.exit(1);
    }
    return;
  }

  const transportArg = process.argv.includes('--transport')
    ? process.argv[process.argv.indexOf('--transport') + 1]
    : 'stdio';

  if (transportArg === 'http') {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      console.error('GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are required for HTTP transport');
      process.exit(1);
    }

    const users = parseUsersFromEnv();
    if (users.size === 0) {
      console.error('No users configured. Set USER_<NAME>_PASSWORD and USER_<NAME>_GOOGLE_REFRESH_TOKEN env vars.');
      process.exit(1);
    }

    // Use first user's password as signing key (arbitrary but stable)
    const signingKey = process.env.MCP_SIGNING_KEY || [...users.values()][0].password;

    const { createHttpApp } = await import('./oauth.js');
    const port = parseInt(process.env.PORT || process.env.MCP_SERVER_PORT || '8000', 10);

    const app = createHttpApp(
      (userId) => {
        const user = users.get(userId);
        const googleAuth = createGoogleAuthFromEnv(user.refreshToken);
        return createMcpServerWithAuth(googleAuth);
      },
      users,
      signingKey
    );

    app.listen(port, '0.0.0.0', () => {
      console.error(`MCP server started in HTTP mode on http://0.0.0.0:${port}`);
      console.error(`Users configured: ${[...users.keys()].join(', ')}`);
    });
  } else {
    try {
      console.error('Starting MCP server in stdio mode...');
      const googleAuth = await loadCredentialsFromFile();
      const server = createMcpServerWithAuth(googleAuth);
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error('MCP server started successfully.');
    } catch (error) {
      console.error('Failed to start server:', error.message);
      process.exit(1);
    }
  }
}

main().catch((error) => {
  console.error('Error in main:', error.message);
  process.exit(1);
});
