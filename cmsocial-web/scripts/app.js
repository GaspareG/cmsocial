'use strict';

/**
 * @ngdoc overview
 * @name cmsocial
 * @description
 * # cmsocial
 *
 * Main module of the application.
 */
angular
  .module('cmsocial', [
    'ngAnimate',
    'ngCookies',
    'ngResource',
    'ngRoute',
    'ngSanitize',
    'ngTouch',
    'ui.router',
    'ui.ace',
    'angular-md5',
  ])
  .constant('API_PREFIX', 'api/')
  .config(function($locationProvider, $stateProvider, $urlRouterProvider) {
    $locationProvider.html5Mode(false); //.hashPrefix('!')
    // FIXME: ui-router ignores hashPrefix for href attributes, so we don't use it (for now)

    $urlRouterProvider
      .when('/tasks/', '/tasks/1')
      .when('/task/{taskName}', '/task/{taskName}/statement')
      .when('/user/{userId}', '/user/{userId}/profile')
      .otherwise('/overview');

    $stateProvider
      .state('overview', {
        url: '/overview',
        templateUrl: 'COMMIT_ID_HERE/views/homepage.html',
        controller: 'HomepageCtrl'
      })
      .state('sso', {
        url: '/sso',
        controller: 'SSOCtrl'
      })
      .state('tasklist', {
        templateUrl: 'COMMIT_ID_HERE/views/tasklist.html',
        controller: 'TasklistSkel'
      })
      .state('tasklist.page', {
        url: '/tasks/{pageNum}?tag&q',
        templateUrl: 'COMMIT_ID_HERE/views/tasks.html',
        controller: 'TasklistPage'
      })
      .state('task', {
        url: '/task/{taskName}',
        templateUrl: 'COMMIT_ID_HERE/views/task.html',
        controller: 'TaskbarCtrl'
      })
      .state('task.statement', {
        url: '/statement',
        templateUrl: 'COMMIT_ID_HERE/views/task.statement.html',
        controller: 'StatementCtrl'
      })
      .state('task.submissions', {
        url: '/submissions',
        templateUrl: 'COMMIT_ID_HERE/views/task.submissions.html',
        controller: 'SubmissionsCtrl'
      })
      .state('task.attachments', {
        url: '/attachments',
        templateUrl: 'COMMIT_ID_HERE/views/task.attachments.html',
        controller: 'AttachmentsCtrl'
      })
      .state('task.stats', {
        url: '/stats',
        templateUrl: 'COMMIT_ID_HERE/views/task.stats.html',
        controller: 'StatsCtrl'
      })
      .state('pre-test', {
        url: '/pre-test',
        templateUrl: 'COMMIT_ID_HERE/views/pre-test.html',
        controller: 'PreTestCtrl'
      })
      .state('logic-quiz', {
        url: '/logic-quiz',
        templateUrl: 'COMMIT_ID_HERE/views/logic-quiz.html',
        controller: 'LogicQuizCtrl'
      })
      .state('user', {
        url: '/user/{userId}',
        templateUrl: 'COMMIT_ID_HERE/views/user.html',
        controller: 'UserbarCtrl'
      })
      .state('user.profile', {
        url: '/profile',
        templateUrl: 'COMMIT_ID_HERE/views/user.profile.html',
        controller: 'UserpageCtrl'
      })

  })
  .controller('HomepageCtrl', function($scope, userManager, contestManager) {
    $scope.me = userManager;
    $scope.cm = contestManager;
  })
  .filter('repext', function() {
    return function(input) {
      return input.replace(/.%l$/, ".(cpp|c|pas)");
    };
  })
  .filter('outcomeToClass', function() {
    return function(input) {
      if (input == "Correct")
        return "correct";
      if (input == "Not correct")
        return "wrong";
      return "partial";
    };
  })
  .filter('timeFmt', function() {
    return function(input) {
      if (input == undefined)
        return "N/A";
      return input.toFixed(3) + "s";
    };
  })
  .filter('memoryFmt', function() {
    return function(input) {
      if (input == undefined)
        return "N/A";
      if (input > 1024 * 1024)
        return (input / (1024 * 1024)).toFixed(1) + " MiB";
      else if (input > 1024)
        return (input / 1024).toFixed(0) + " KiB";
      return input + " B";
    };
  })
  .filter('dateFmt', function() {
    return function(input) {
      var d = new Date(1000 * (+input));
      if (d.toDateString() == new Date(Date.now()).toDateString())
        return "oggi, " + ('0' + d.getHours()).substr(-2) + ":" + ('0' + d.getMinutes()).substr(-2);
      d.setDate(d.getDate() + 1);
      if (d.toDateString() == new Date(Date.now()).toDateString())
        return "ieri, " + ('0' + d.getHours()).substr(-2) + ":" + ('0' + d.getMinutes()).substr(-2);
      d.setDate(d.getDate() - 1);
      return ('0' + d.getDate()).substr(-2) + "/" + ('0' + (d.getMonth() + 1)).substr(-2) +
        "/" + d.getFullYear() + ", " + ('0' + d.getHours()).substr(-2) + ":" +
        ('0' + d.getMinutes()).substr(-2);
    };
  });
